// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
// This software is provided solely for performance evaluation and educational purposes.
// See the repository LICENSE file for reuse terms.

#include <iostream>
#include <string>
#include <thread>
#include <string_view>
#include <stdexcept>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <vector>
#include <deque>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <exception>
#include <fstream>
#include <random>
#include <filesystem>
#include <array>
#include <bit>
#include <optional>
#include <span>
#include <memory>
#include <limits>
#include <type_traits>
#include <utility>
#include <poll.h>
#include <pthread.h>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/random.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <boost/unordered/unordered_flat_map.hpp>


#include "tcp/common_config.h"
#include "tcp/mapping_protocol.h"
#include "tcp/mapping_store.h"
#include "tcp/server_epoll.h"
#include "tcp/server_runtime.h"
#include "tcp/unique_fd.h"
#include "tls/secure_transport.h"
#include "epoll_runtime/connection_id.h"

namespace {
constexpr auto kDefaultIdleTimeout = std::chrono::seconds(15);

// Chooses a conservative default worker count from available CPU concurrency.
std::size_t default_event_loop_count() {
    const unsigned int hardware_threads = std::thread::hardware_concurrency();
    return hardware_threads == 0 ? 1U : hardware_threads;
}

// Rejects configurations that cannot fit their requested sockets in the
// process descriptor limit, including conservative per-worker overhead.
void validate_file_descriptor_capacity(std::size_t event_loop_count,
                                       std::size_t max_connections_per_loop) {
    if (max_connections_per_loop >
        (std::numeric_limits<std::size_t>::max() - 32U) / event_loop_count) {
        throw std::invalid_argument("configured connection capacity overflows size_t");
    }
    const std::size_t connections = event_loop_count * max_connections_per_loop;
    constexpr std::size_t kDescriptorsPerLoop = 4;
    if (event_loop_count >
        (std::numeric_limits<std::size_t>::max() - connections - 32U) /
            kDescriptorsPerLoop) {
        throw std::invalid_argument("configured descriptor capacity overflows size_t");
    }
    const std::size_t required = connections + event_loop_count * kDescriptorsPerLoop + 32U;
    struct rlimit limit {};
    if (::getrlimit(RLIMIT_NOFILE, &limit) < 0) {
        throw std::runtime_error(std::string("getrlimit(RLIMIT_NOFILE) failed: ") +
                                 std::strerror(errno));
    }
    if (limit.rlim_cur != RLIM_INFINITY &&
        required > static_cast<std::size_t>(limit.rlim_cur)) {
        throw std::runtime_error(
            "RLIMIT_NOFILE soft limit " + std::to_string(limit.rlim_cur) +
            " is below required descriptor capacity " + std::to_string(required) +
            "; raise ulimit -n or reduce --event-loops/--max-connections-per-loop");
    }
}

// Parses a base-10 CLI value; text is the raw input and arg_name labels errors.
int parse_int_arg(const char* text, const char* arg_name) {
    try {
        std::size_t pos = 0;
        const std::string value(text);
        const int parsed = std::stoi(value, &pos, 10);
        if (pos != value.size()) {
            throw std::invalid_argument("trailing characters");
        }
        return parsed;
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string(arg_name) + " must be a valid integer");
    }
}

} // namespace

void print_server_usage(std::ostream& output, std::string_view program) {
    output
        << "Usage:\n"
        << "  " << program << " --listen <port> [options]\n"
        << "  " << program << " --export-keys <count> [options]\n\n"
        << "Options:\n"
        << "  -h, --help                         Show this help and exit\n"
        << "  --listen <port>                    Listen on TCP port 1..65535\n"
        << "  --transport <tls|tcp>              Transport (default: tls; tcp is insecure)\n"
        << "  --tls-cert <path>                  Server certificate chain for TLS\n"
        << "  --tls-key <path>                   Server private key for TLS\n"
        << "  --tls-key-passphrase-file <path>   Owner-only runtime credential file\n"
        << "  --tls-client-ca <path>             CA bundle trusted for client mTLS certs\n"
        << "  --tls-client-crl <path>            Optional PEM CRL for client certificates\n"
        << "  --tls-client-allowlist <path>      Required exact URI:/DNS: SAN allowlist\n"
        << "  --tls-version <policy>             tls13 (default), tls12, or tls12-or-tls13\n"
        << "  --tls-allow-tls12                  Alias for --tls-version tls12-or-tls13\n"
        << "  --mapping-file <path>              Mapping file (default: "
        << tcp_common::kDefaultServerMappingFile << ")\n"
        << "  --mapping-loader <mode>            ifstream, mmap, or mmap-view\n"
        << "                                      (default: mmap-view)\n"
        << "  --regen-mapping                    Regenerate the mapping file\n"
        << "  --mapping-entries <count>          Entries generated with --regen-mapping\n"
        << "  --event-loops <count>              Epoll worker count (default: CPU count)\n"
        << "  --max-connections-per-loop <count> Connection limit per epoll worker\n"
        << "                                      (default: 10000)\n"
        << "  --idle-timeout-seconds <seconds>   Positive idle timeout (default: "
        << kDefaultIdleTimeout.count() << ")\n"
        << "  --export-keys <count>              Export request keys for tcp_client\n"
        << "  --keys-output <path>               Export destination (default: "
        << tcp_common::kDefaultClientKeysFile << ")\n\n"
        << "Examples:\n"
        << "  " << program << " --listen 23456 --transport tcp --mapping-file "
        << tcp_common::kDefaultServerMappingFile << "\n"
        << "  " << program
        << " --listen 23456 --transport tcp --mapping-file server"
           " --mapping-loader mmap-view\n"
        << "  " << program
        << " --regen-mapping --mapping-entries 500000 --export-keys 500000\n\n"
        << "Options use a space between the option and its value; for example,\n"
        << "--mapping-file server (not --mapping-file=server).\n";
}

int main(int argc, char* argv[]) {
    try {
        int listen_port = 0;
        bool has_listen = false;
        bool force_regen_mapping = false;
        bool print_keys_requested = false;
        bool keys_output_requested = false;
        bool mapping_entries_requested = false;
        std::size_t print_keys_count = 0;
        std::size_t mapping_entries = kDefaultMappingEntries;
        std::size_t event_loop_count = default_event_loop_count();
        std::size_t max_connections_per_loop = 10000;
        std::string mapping_file = tcp_common::kDefaultServerMappingFile;
        std::string keys_output_file = tcp_common::kDefaultClientKeysFile;
        MappingLoadMode mapping_load_mode = MappingLoadMode::MMapView;
        std::chrono::seconds idle_timeout = kDefaultIdleTimeout;
        secure_transport::Mode transport_mode = secure_transport::Mode::Tls;
        secure_transport::ServerTlsConfig tls_config;
        std::string tls_client_allowlist_file;
        std::string tls_key_passphrase_file;
        bool tls_version_option_set = false;

        if (argc < 2) {
            throw std::invalid_argument("no mode or option was provided");
        }

        for (int i = 1; i < argc; ++i) {
            const std::string_view arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                print_server_usage(std::cout, argv[0]);
                return 0;
            } else if (arg == "--listen") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--listen requires a port value");
                }
                listen_port = parse_int_arg(argv[i + 1], "--listen");
                has_listen = true;
                ++i;
            } else if (arg == "--transport") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--transport requires tls or tcp");
                }
                transport_mode = secure_transport::parse_mode(argv[++i]);
            } else if (arg == "--tls-cert") {
                if (i + 1 >= argc) throw std::invalid_argument("--tls-cert requires a path");
                tls_config.certificate_chain_file = argv[++i];
            } else if (arg == "--tls-key") {
                if (i + 1 >= argc) throw std::invalid_argument("--tls-key requires a path");
                tls_config.private_key_file = argv[++i];
            } else if (arg == "--tls-key-passphrase-file") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--tls-key-passphrase-file requires a path");
                }
                tls_key_passphrase_file = argv[++i];
            } else if (arg == "--tls-client-ca") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--tls-client-ca requires a path");
                }
                tls_config.client_ca_file = argv[++i];
            } else if (arg == "--tls-client-crl") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--tls-client-crl requires a path");
                }
                tls_config.client_crl_file = argv[++i];
            } else if (arg == "--tls-client-allowlist") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--tls-client-allowlist requires a path");
                }
                tls_client_allowlist_file = argv[++i];
            } else if (arg == "--tls-allow-tls12") {
                tls_config.version_policy = secure_transport::TlsVersionPolicy::Tls12And13;
                tls_version_option_set = true;
            } else if (arg == "--tls-version") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--tls-version requires a policy");
                }
                tls_config.version_policy =
                    secure_transport::parse_tls_version_policy(argv[++i]);
                tls_version_option_set = true;
            } else if (arg == "--mapping-file") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--mapping-file requires a file path");
                }
                mapping_file = argv[i + 1];
                ++i;
            } else if (arg == "--mapping-loader") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--mapping-loader requires one value: ifstream, mmap, or mmap-view");
                }
                const std::string_view loader = argv[i + 1];
                if (loader == "ifstream") {
                    mapping_load_mode = MappingLoadMode::Ifstream;
                } else if (loader == "mmap") {
                    mapping_load_mode = MappingLoadMode::MMap;
                } else if (loader == "mmap-view") {
                    mapping_load_mode = MappingLoadMode::MMapView;
                } else {
                    throw std::invalid_argument("--mapping-loader must be one of: ifstream, mmap, mmap-view");
                }
                ++i;
            } else if (arg == "--regen-mapping") {
                force_regen_mapping = true;
            } else if (arg == "--mapping-entries") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--mapping-entries requires a numeric value");
                }
                const int requested = parse_int_arg(argv[i + 1], "--mapping-entries");
                if (requested <= 0 ||
                    static_cast<std::uint32_t>(requested) > tcp_common::kMaxMappingEntries) {
                    throw std::invalid_argument(
                        "--mapping-entries must be in range 1.." +
                        std::to_string(tcp_common::kMaxMappingEntries));
                }
                mapping_entries = static_cast<std::size_t>(requested);
                mapping_entries_requested = true;
                ++i;
            } else if (arg == "--event-loops") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--event-loops requires a numeric value");
                }
                const int requested = parse_int_arg(argv[i + 1], "--event-loops");
                if (requested <= 0) {
                    throw std::invalid_argument("--event-loops must be positive");
                }
                event_loop_count = static_cast<std::size_t>(requested);
                ++i;
            } else if (arg == "--max-connections-per-loop") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--max-connections-per-loop requires a numeric value");
                }
                const int requested = parse_int_arg(argv[i + 1], "--max-connections-per-loop");
                if (requested <= 0) {
                    throw std::invalid_argument("--max-connections-per-loop must be positive");
                }
                max_connections_per_loop = static_cast<std::size_t>(requested);
                ++i;
            } else if (arg == "--idle-timeout-seconds") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--idle-timeout-seconds requires a numeric value");
                }
                const int requested = parse_int_arg(argv[i + 1], "--idle-timeout-seconds");
                if (requested <= 0) {
                    throw std::invalid_argument("--idle-timeout-seconds must be positive");
                }
                idle_timeout = std::chrono::seconds(requested);
                ++i;
            } else if (arg == "--export-keys" || arg == "--print-keys") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--export-keys requires a numeric value");
                }
                const int requested = parse_int_arg(argv[i + 1], "--export-keys");
                if (requested <= 0) {
                    throw std::invalid_argument("--export-keys must be positive");
                }
                print_keys_count = static_cast<std::size_t>(requested);
                print_keys_requested = true;
                ++i;
            } else if (arg == "--keys-output") {
                if (i + 1 >= argc) {
                    throw std::invalid_argument("--keys-output requires a file path");
                }
                keys_output_file = argv[i + 1];
                if (keys_output_file.empty()) {
                    throw std::invalid_argument("--keys-output path must not be empty");
                }
                keys_output_requested = true;
                ++i;
            } else {
                throw std::invalid_argument("Unknown argument: " + std::string(arg));
            }
        }

        if (!has_listen && !print_keys_requested) {
            throw std::invalid_argument(
                "Provide at least one mode: --listen <port> and/or --export-keys <N>");
        }

        if (keys_output_requested && !print_keys_requested) {
            throw std::invalid_argument("--keys-output requires --export-keys");
        }

        if (mapping_entries_requested && !force_regen_mapping) {
            throw std::invalid_argument("--mapping-entries requires --regen-mapping");
        }

        if (has_listen && (listen_port <= 0 || listen_port > 65535)) {
            throw std::invalid_argument("Port must be in range 1..65535");
        }

        std::shared_ptr<secure_transport::TlsContextStore> tls_contexts;
        if (has_listen && transport_mode == secure_transport::Mode::Tls) {
            if (tls_config.certificate_chain_file.empty() ||
                tls_config.private_key_file.empty() || tls_config.client_ca_file.empty() ||
                tls_client_allowlist_file.empty()) {
                throw std::invalid_argument(
                    "TLS mode requires --tls-cert, --tls-key, --tls-client-ca, and "
                    "--tls-client-allowlist");
            }
            if (!tls_key_passphrase_file.empty()) {
                tls_config.private_key_passphrase =
                    secure_transport::load_private_key_passphrase_file(
                        tls_key_passphrase_file);
            }
            tls_config.allowed_client_sans =
                tcp_server::load_tls_client_allowlist(tls_client_allowlist_file);
            tls_contexts = std::make_shared<secure_transport::TlsContextStore>(
                secure_transport::TlsContext::make_server(tls_config));
        } else if (transport_mode == secure_transport::Mode::Tcp &&
                   (!tls_config.certificate_chain_file.empty() ||
                    !tls_config.private_key_file.empty() || !tls_config.client_ca_file.empty() ||
                    !tls_config.client_crl_file.empty() || !tls_client_allowlist_file.empty() ||
                    !tls_key_passphrase_file.empty() || tls_version_option_set)) {
            throw std::invalid_argument("--tls-* options cannot be used with --transport tcp");
        }

        if (has_listen) {
            validate_file_descriptor_capacity(event_loop_count,
                                              max_connections_per_loop);
        }

        UniqueFd port_instance_lock;
        if (has_listen) {
            // Acquire this before loading or exporting so a conflicting server
            // cannot leave behind a key file for a mapping it never served.
            port_instance_lock = tcp_server::acquire_port_instance_lock(listen_port);
        }

        initialize_request_mapping(mapping_file,
                                   force_regen_mapping,
                                   mapping_load_mode,
                                   mapping_entries);

        if (print_keys_requested) {
            print_request_keys(print_keys_count, keys_output_file);
        }

        if (!has_listen) {
            return 0;
        }

        auto protocol_factory = std::make_shared<MappingProtocolFactory>();
        tcp_server::start_listen(listen_port,
                     event_loop_count,
                     idle_timeout,
                     max_connections_per_loop,
                     transport_mode,
                     tls_config,
                     tls_client_allowlist_file,
                     tls_key_passphrase_file,
                     std::move(tls_contexts),
                     std::move(protocol_factory),
                     std::move(port_instance_lock));
        return 0;
    } catch (const std::invalid_argument& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        std::cerr << '\n';
        print_server_usage(std::cerr, argc > 0 ? argv[0] : "tcp_server_epoll");
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }
}
