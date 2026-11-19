// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "epoll_runtime/protocol.h"
#include "tcp/unique_fd.h"
#include "tls/secure_transport.h"

namespace tcp_server {

// Reads and validates the server's URI:/DNS: client SAN allowlist.
std::vector<std::string> load_tls_client_allowlist(const std::string& path);

// Acquires an exclusive process-level lock for a server listen port.
UniqueFd acquire_port_instance_lock(int listen_port);

// Starts the configured epoll workers and coordinates their shutdown.
void start_listen(
    int listen_port,
    std::size_t event_loop_count,
    std::chrono::seconds idle_timeout,
    std::size_t max_connections_per_loop,
    secure_transport::Mode transport_mode,
    const secure_transport::ServerTlsConfig& tls_config,
    const std::string& tls_client_allowlist_file,
    const std::string& tls_key_passphrase_file,
    std::shared_ptr<secure_transport::TlsContextStore> tls_contexts,
    std::shared_ptr<const server_runtime::ProtocolFactory> protocol_factory,
    UniqueFd port_instance_lock);

} // namespace tcp_server
