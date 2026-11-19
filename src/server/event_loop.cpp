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
#include "tcp/unique_fd.h"
#include "tls/secure_transport.h"
#include "epoll_runtime/connection_id.h"

#include "tcp/server_runtime.h"

namespace {
constexpr std::size_t kAcceptBatchSize = 256;
constexpr std::size_t kMaxEpollEvents = 4096;
constexpr std::size_t kMaxReadBytesPerEvent = 64 * 1024;
constexpr std::size_t kMaxWriteBytesPerEvent = 64 * 1024;
constexpr std::size_t kMaxDeferredTlsReadsPerIteration = 256;
constexpr std::size_t kTimingWheelSlots = 256;
constexpr int kClientReceiveBufferBytes = 4096;
constexpr auto kEpollWaitTimeout = std::chrono::milliseconds(250);
constexpr auto kGraceShutdownTimeout = std::chrono::seconds(30);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);
constexpr auto kAcceptCapacityBackoff = std::chrono::milliseconds(10);
constexpr auto kRequestCompletionTimeout = std::chrono::seconds(10);
constexpr auto kResponseDrainTimeout = std::chrono::seconds(30);
constexpr auto kTlsHandshakeTimeout = std::chrono::seconds(10);
constexpr std::size_t kMaxTlsHandshakesPerLoop = 1024;
constexpr std::size_t kMaxTlsErrorLogsPerLoop = 20;
static_assert(tcp_common::kMaxPayloadSize <=
              static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max()));

enum class ShutdownState : std::uint8_t { Running, Draining, Stopping };
std::atomic<ShutdownState> g_shutdown_state{ShutdownState::Running};
std::atomic<std::int64_t> g_drain_deadline_ns{0};

// Pins a worker to one CPU from the process's allowed affinity set. Failure is
// non-fatal because containers and restricted service managers may forbid it.
void pin_current_thread(std::size_t worker_index) noexcept {
    cpu_set_t allowed{};
    if (::sched_getaffinity(0, sizeof(allowed), &allowed) < 0) {
        return;
    }
    const int allowed_count = CPU_COUNT(&allowed);
    if (allowed_count <= 0) {
        return;
    }
    const std::size_t target_index = worker_index % static_cast<std::size_t>(allowed_count);
    std::size_t seen = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed)) {
            continue;
        }
        if (seen++ != target_index) {
            continue;
        }
        cpu_set_t target{};
        CPU_SET(cpu, &target);
        (void)::pthread_setaffinity_np(::pthread_self(), sizeof(target), &target);
        return;
    }
}

// Blocks termination signals for the process and exposes them through a
// nonblocking signalfd that the coordinator can poll safely.
class SignalFd {
public:
    SignalFd() {
        sigset_t signals{};
        ::sigemptyset(&signals);
        ::sigaddset(&signals, SIGINT);
        ::sigaddset(&signals, SIGTERM);
        ::sigaddset(&signals, SIGHUP);
        ::sigaddset(&signals, SIGQUIT);
        const int mask_error =
            ::pthread_sigmask(SIG_BLOCK, &signals, &previous_mask_);
        if (mask_error != 0) {
            throw std::runtime_error(std::string("pthread_sigmask failed while blocking ") +
                                     "termination signals: " + std::strerror(mask_error));
        }
        mask_installed_ = true;
        const int signal_fd =
            ::signalfd(-1, &signals, SFD_CLOEXEC | SFD_NONBLOCK);
        if (signal_fd < 0) {
            const int signal_error = errno;
            (void)::pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
            mask_installed_ = false;
            throw std::runtime_error(std::string("signalfd failed: ") +
                                     std::strerror(signal_error));
        }
        fd_.reset(signal_fd);
    }

    ~SignalFd() noexcept {
        fd_.reset();
        if (mask_installed_) {
            (void)::pthread_sigmask(SIG_SETMASK, &previous_mask_, nullptr);
        }
    }

    SignalFd(const SignalFd&) = delete;
    SignalFd& operator=(const SignalFd&) = delete;
    SignalFd(SignalFd&&) = delete;
    SignalFd& operator=(SignalFd&&) = delete;
    int fd() const noexcept { return fd_.get(); }

private:
    UniqueFd fd_;
    sigset_t previous_mask_{};
    bool mask_installed_ = false;
};

// Returns the monotonic clock in nanoseconds for lock-free shutdown deadlines.
std::int64_t steady_clock_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Advances global shutdown state on each termination signal: the first starts
// draining and a later signal requests immediate stopping.
void begin_graceful_shutdown() noexcept {
    ShutdownState expected = ShutdownState::Running;
    if (g_shutdown_state.compare_exchange_strong(expected, ShutdownState::Draining,
                                                  std::memory_order_acq_rel)) {
        const auto deadline = steady_clock_ns() +
            std::chrono::duration_cast<std::chrono::nanoseconds>(kGraceShutdownTimeout).count();
        g_drain_deadline_ns.store(deadline, std::memory_order_release);
    } else {
        g_shutdown_state.store(ShutdownState::Stopping, std::memory_order_release);
    }
}

// Reports whether error_code indicates temporary descriptor or memory pressure
// for which accepting should pause rather than terminate the server.
bool is_resource_exhaustion_error(int error_code) {
    switch (error_code) {
    case EMFILE:
    case ENFILE:
    case ENOMEM:
    case ENOBUFS:
        return true;
    default:
        return false;
    }
}

} // namespace

std::vector<std::string> tcp_server::load_tls_client_allowlist(const std::string& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("failed to open TLS client SAN allowlist: " + path);
    }
    std::vector<std::string> identities;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;
        if (line.size() > 2048 ||
            (line.rfind("URI:", 0) != 0 && line.rfind("DNS:", 0) != 0)) {
            throw std::runtime_error(
                "TLS client allowlist entries must be URI:<value> or DNS:<value>");
        }
        identities.push_back(std::move(line));
        if (identities.size() > 100000) {
            throw std::runtime_error("TLS client SAN allowlist has too many entries");
        }
    }
    if (!input.eof() || identities.empty()) {
        throw std::runtime_error("TLS client SAN allowlist is empty or unreadable: " + path);
    }
    return identities;
}


enum class TlsRetryOperation : std::uint8_t { None, Read, Write };

// Lazily allocated only for TLS connections that need to combine multiple
// application slices into one SSL_write_ex call. The bytes remain unchanged
// across WANT_READ/WANT_WRITE retries, as required by OpenSSL.
struct TlsCoalescedWrite {
    std::vector<std::byte> bytes;
};

// Holds transport, injected protocol, TLS retry, and timeout state for one
// client. Application parsing and response construction live behind protocol.
struct ConnectionState {
    ConnectionState(UniqueFd socket_value,
                    std::uint32_t generation_value,
                    secure_transport::Mode mode,
                    std::shared_ptr<secure_transport::TlsContext> tls_context,
                    const server_runtime::ProtocolFactory& protocol_factory)
        : socket(std::move(socket_value)), generation(generation_value),
          protocol(protocol_factory.create()) {
        if (protocol == nullptr) {
            throw std::runtime_error("protocol factory returned a null connection");
        }
        if (mode == secure_transport::Mode::Tls) {
            tls = std::make_unique<secure_transport::TlsSession>(
                std::move(tls_context), socket.fd(), true);
            tls_established = false;
        }
    }

    [[nodiscard]] int fd() const noexcept { return socket.get(); }

    UniqueFd socket;
    std::uint32_t generation = 0;
    std::unique_ptr<secure_transport::TlsSession> tls;
    std::unique_ptr<server_runtime::ProtocolConnection> protocol;
    bool tls_established = true;
    bool tls_wants_write = false;
    bool tls_handshake_counted = false;
    TlsRetryOperation tls_retry_operation = TlsRetryOperation::None;
    std::uint64_t tls_handshake_deadline_tick = 0;
    std::uint64_t expiration_tick = 0;
    std::uint64_t idle_deadline_tick = 0;
    std::uint64_t request_deadline_tick = 0;
    std::uint64_t response_deadline_tick = 0;
    int wheel_previous = -1;
    int wheel_next = -1;
    std::uint8_t wheel_slot = 0;
    bool wheel_scheduled = false;
    bool peer_write_closed = false;
    std::uint32_t registered_events = 0;
    bool buffered_tls_read_queued = false;
    std::shared_ptr<const void> output_lifetime;
    std::unique_ptr<TlsCoalescedWrite> tls_coalesced_write;

    [[nodiscard]] bool has_responses() const noexcept { return protocol->has_output(); }
};

static_assert(!std::is_copy_constructible_v<ConnectionState>);
static_assert(!std::is_copy_assignable_v<ConnectionState>);
static_assert(std::is_nothrow_move_constructible_v<ConnectionState>);
static_assert(std::is_nothrow_move_assignable_v<ConnectionState>);

// Owns live connections inline in one cache-local open-addressed allocation,
// avoiding a separate heap node for every accepted descriptor.
class ConnectionTable {
public:
    using Storage = boost::unordered_flat_map<int, ConnectionState>;
    using Iterator = Storage::iterator;
    // Takes ownership of socket and creates its state in the descriptor slot.
    ConnectionState& emplace(UniqueFd socket,
                             std::uint32_t generation,
                             secure_transport::Mode mode,
                             std::shared_ptr<secure_transport::TlsContext> tls_context,
                             const server_runtime::ProtocolFactory& protocol_factory) {
        const int fd = socket.get();
        if (fd < 0) {
            throw std::runtime_error("cannot store negative file descriptor");
        }
        auto [it, inserted] = entries_.try_emplace(
            fd, std::move(socket), generation, mode, std::move(tls_context), protocol_factory);
        if (!inserted) {
            throw std::runtime_error("duplicate connection state for fd " + std::to_string(fd));
        }
        return it->second;
    }

    // Returns mutable state for fd, or nullptr when its slot is empty/stale.
    ConnectionState* find(int fd) noexcept {
        if (fd < 0) {
            return nullptr;
        }

        const auto it = entries_.find(fd);
        return it == entries_.end() ? nullptr : &it->second;
    }

    // Returns read-only state for fd, or nullptr when its slot is empty/stale.
    const ConnectionState* find(int fd) const noexcept {
        if (fd < 0) {
            return nullptr;
        }

        const auto it = entries_.find(fd);
        return it == entries_.end() ? nullptr : &it->second;
    }

    // Releases the connection stored for fd if the descriptor still matches.
    void erase(int fd) noexcept {
        entries_.erase(fd);
    }

    void clear() noexcept {
        entries_.clear();
    }

    std::size_t size() const noexcept {
        return entries_.size();
    }

    void reserve(std::size_t count) {
        entries_.reserve(count);
    }

    auto begin() noexcept { return entries_.begin(); }
    auto end() noexcept { return entries_.end(); }
    Iterator erase(Iterator it) noexcept { return entries_.erase(it); }

private:
    Storage entries_;
};

// Creates the close-on-exec epoll descriptor used by one event-loop worker.
UniqueFd create_epoll_handle() {
    const int epoll_fd = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        throw std::runtime_error(std::string("epoll_create1 failed: ") + std::strerror(errno));
    }
    return UniqueFd(epoll_fd);
}

// Creates a nonblocking eventfd used for wakeups or worker completion signals.
UniqueFd create_event_handle() {
    const int event_fd = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (event_fd < 0) {
        throw std::runtime_error(std::string("eventfd failed: ") + std::strerror(errno));
    }
    return UniqueFd(event_fd);
}

// Acquires a process-level advisory lock keyed by listen_port so two benchmark
// instances cannot unintentionally serve different mappings on the same port.
UniqueFd tcp_server::acquire_port_instance_lock(int listen_port) {
    const std::string lock_path =
        "/tmp/tcp_server_epoll." + std::to_string(static_cast<unsigned long>(::getuid())) +
        "." + std::to_string(listen_port) + ".lock";
    UniqueFd lock_fd(::open(lock_path.c_str(),
                            O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                            S_IRUSR | S_IWUSR));
    if (!lock_fd) {
        throw std::runtime_error("failed to open per-port instance lock " + lock_path +
                                 ": " + std::strerror(errno));
    }
    if (::flock(lock_fd.fd(), LOCK_EX | LOCK_NB) < 0) {
        const int lock_errno = errno;
        if (lock_errno == EWOULDBLOCK || lock_errno == EAGAIN) {
            throw std::runtime_error(
                "another tcp_server_epoll instance is already using port " +
                std::to_string(listen_port));
        }
        throw std::runtime_error("failed to lock port " + std::to_string(listen_port) +
                                 ": " + std::strerror(lock_errno));
    }
    return lock_fd;
}

// Creates, configures, binds, and listens on a nonblocking IPv4 socket for
// listen_port; SO_REUSEPORT permits one listener per event-loop worker.
UniqueFd create_reuseport_listener(int listen_port) {
    const int listen_fd =
        ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (listen_fd < 0) {
        throw std::runtime_error(std::string("socket failed: ") + std::strerror(errno));
    }

    UniqueFd listen_socket(listen_fd);

    int enable = 1;
    if (::setsockopt(listen_socket.fd(), SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(SO_REUSEADDR) failed: ") +
                                 std::strerror(errno));
    }
    if (::setsockopt(listen_socket.fd(), SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(SO_REUSEPORT) failed: ") +
                                 std::strerror(errno));
    }
    if (::setsockopt(listen_socket.fd(), SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(SO_KEEPALIVE) failed: ") +
                                 std::strerror(errno));
    }
    if (::setsockopt(listen_socket.fd(), IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(TCP_NODELAY) failed: ") +
                                 std::strerror(errno));
    }

    sockaddr_in listen_addr{};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(static_cast<std::uint16_t>(listen_port));
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(listen_socket.fd(),
               reinterpret_cast<sockaddr*>(&listen_addr),
               sizeof(listen_addr)) < 0) {
        throw std::runtime_error(std::string("bind failed: ") + std::strerror(errno));
    }

    if (::listen(listen_socket.fd(), SOMAXCONN) < 0) {
        throw std::runtime_error(std::string("listen failed: ") + std::strerror(errno));
    }

    return listen_socket;
}

// Applies memory-conscious options to an accepted client socket. Linux doubles
// SO_RCVBUF internally for bookkeeping, but the requested value still bounds
// the advertised receive window far below the distribution default.
void configure_client_socket(int fd) {
    const int enable = 1;
    const int receive_buffer = kClientReceiveBufferBytes;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF,
                     &receive_buffer, sizeof(receive_buffer)) < 0) {
        throw std::runtime_error(std::string("setsockopt(SO_RCVBUF) failed: ") +
                                 std::strerror(errno));
    }
    if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(SO_KEEPALIVE) failed: ") +
                                 std::strerror(errno));
    }
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable)) < 0) {
        throw std::runtime_error(std::string("setsockopt(TCP_NODELAY) failed: ") +
                                 std::strerror(errno));
    }
}

// Linux-specific implementation of one isolated epoll worker, including its
// listener, wake channel, connection table, and idle-timeout wheel.
class EventLoop::Impl {
public:
    // Builds worker loop_id with a reuse-port listener on listen_port, the
    // requested idle_timeout, and a hard max_connections capacity.
    Impl(std::size_t loop_id,
         int listen_port,
         std::chrono::seconds idle_timeout,
         std::size_t max_connections,
         secure_transport::Mode transport_mode,
         std::shared_ptr<secure_transport::TlsContextStore> tls_contexts,
         std::shared_ptr<const server_runtime::ProtocolFactory> protocol_factory)
        : loop_id_(loop_id),
          name_("EpollLoop-" + std::to_string(loop_id)),
          idle_timeout_(idle_timeout),
          max_connections_(max_connections),
          transport_mode_(transport_mode),
          tls_contexts_(std::move(tls_contexts)),
          protocol_factory_(std::move(protocol_factory)),
          epoll_fd_(create_epoll_handle()),
          listen_socket_(create_reuseport_listener(listen_port)),
          wake_fd_(create_event_handle()),
          reserve_fd_(open_reserve_fd()) {
        if (protocol_factory_ == nullptr) {
            throw std::invalid_argument("event loop requires a protocol factory");
        }
        connections_.reserve(max_connections_);
        timing_wheel_.fill(-1);
        last_expired_tick_ = current_tick();
        register_fd(listen_socket_.fd(), EPOLLIN);
        listener_registered_ = true;
        register_fd(wake_fd_.fd(), EPOLLIN);
    }

    ~Impl() noexcept {
        shutdown_all_connections();
        if (listen_socket_.fd() >= 0) {
            remove_fd(listen_socket_.fd());
        }
        remove_fd(wake_fd_.fd());
    }

    // Dispatches epoll events until stop_token or global shutdown completes.
    void run(std::stop_token stop_token) {
        std::vector<epoll_event> events(kMaxEpollEvents);

        while (true) {
            if (stop_token.stop_requested()) {
                g_shutdown_state.store(ShutdownState::Stopping,
                                       std::memory_order_release);
            }
            const ShutdownState shutdown = g_shutdown_state.load(std::memory_order_acquire);
            if (shutdown != ShutdownState::Running) {
                stop_accepting();
                if (connections_.size() == 0 || shutdown == ShutdownState::Stopping ||
                    steady_clock_ns() >= g_drain_deadline_ns.load(std::memory_order_acquire)) {
                    shutdown_all_connections();
                    return;
                }
            } else {
                maybe_resume_accepting();
            }
            const int wait_timeout = buffered_tls_reads_.empty()
                ? static_cast<int>(kEpollWaitTimeout.count()) : 0;
            const int ready = ::epoll_wait(
                epoll_fd_.fd(),
                events.data(),
                static_cast<int>(events.size()),
                wait_timeout);

            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("epoll_wait failed: ") + std::strerror(errno));
            }

            for (int i = 0; i < ready; ++i) {
                handle_event(events[static_cast<std::size_t>(i)]);
            }

            process_buffered_tls_reads();

            expire_idle_connections();
        }
    }

    // Signals the worker's eventfd so a blocked epoll_wait returns promptly.
    void wake() noexcept {
        const std::uint64_t one = 1;
        for (;;) {
            const ssize_t written = ::write(wake_fd_.fd(), &one, sizeof(one));
            if (written == static_cast<ssize_t>(sizeof(one))) {
                return;
            }
            if (written < 0 && errno == EINTR) {
                continue;
            }
            // EAGAIN means the eventfd counter is already nonzero, so the loop
            // is guaranteed to wake. Other failures can only be logged safely
            // by the coordinator; wake itself is intentionally noexcept.
            return;
        }
    }

    [[nodiscard]] EventLoopStats stats() const noexcept {
        return stats_;
    }

private:
    // Adds fd to this worker's epoll set with the requested event mask.
    void register_fd(int fd, std::uint32_t events) {
        epoll_event ev{};
        ev.events = events;
        ev.data.u64 = epoll_runtime::encode(epoll_runtime::ConnectionId{
            .descriptor = static_cast<std::uint32_t>(fd), .generation = 0});
        if (::epoll_ctl(epoll_fd_.fd(), EPOLL_CTL_ADD, fd, &ev) < 0) {
            throw std::runtime_error(std::string("epoll_ctl(ADD) failed: ") + std::strerror(errno));
        }
    }

    // Adds client fd with events, logging and returning false on failure.
    bool try_register_connection_fd(int fd, std::uint32_t generation,
                                    std::uint32_t events) noexcept {
        epoll_event ev{};
        ev.events = events;
        ev.data.u64 = epoll_runtime::encode(epoll_runtime::ConnectionId{
            .descriptor = static_cast<std::uint32_t>(fd), .generation = generation});
        if (::epoll_ctl(epoll_fd_.fd(), EPOLL_CTL_ADD, fd, &ev) == 0) {
            return true;
        }
        const int error = errno;
        std::cerr << name_ << " epoll_ctl(ADD) failed for fd " << fd
                  << ": " << std::strerror(error) << std::endl;
        return false;
    }

    // Replaces fd's epoll interest mask with events, returning success status.
    bool try_modify_fd(int fd, std::uint32_t generation,
                       std::uint32_t events) noexcept {
        epoll_event ev{};
        ev.events = events;
        ev.data.u64 = epoll_runtime::encode(epoll_runtime::ConnectionId{
            .descriptor = static_cast<std::uint32_t>(fd), .generation = generation});
        if (::epoll_ctl(epoll_fd_.fd(), EPOLL_CTL_MOD, fd, &ev) == 0) {
            return true;
        }
        const int error = errno;
        std::cerr << name_ << " epoll_ctl(MOD) failed for fd " << fd
                  << ": " << std::strerror(error) << std::endl;
        return false;
    }

    // Best-effort removal of fd from this worker's epoll set.
    void remove_fd(int fd) noexcept {
        ::epoll_ctl(epoll_fd_.fd(), EPOLL_CTL_DEL, fd, nullptr);
    }

    // Consumes accumulated eventfd notifications after a wake event.
    void drain_wake_fd() noexcept {
        std::uint64_t value = 0;
        for (;;) {
            const ssize_t result = ::read(wake_fd_.fd(), &value, sizeof(value));
            if (result == static_cast<ssize_t>(sizeof(value))) {
                continue;
            }
            if (result < 0 && errno == EINTR) {
                continue;
            }
            return;
        }
    }

    // Temporarily removes the listener from epoll for duration after capacity
    // or resource pressure.
    void pause_accepting(std::chrono::milliseconds duration) noexcept {
        if (listen_socket_.fd() < 0) {
            return;
        }
        if (listener_registered_) {
            remove_fd(listen_socket_.fd());
            listener_registered_ = false;
        }
        const auto requested_deadline = std::chrono::steady_clock::now() + duration;
        accept_resume_time_ = std::max(accept_resume_time_, requested_deadline);
    }

    // Re-registers the listener after its backoff deadline, if still running.
    void maybe_resume_accepting() {
        if (listen_socket_.fd() < 0 || listener_registered_ ||
            std::chrono::steady_clock::now() < accept_resume_time_) {
            return;
        }
        register_fd(listen_socket_.fd(), EPOLLIN);
        listener_registered_ = true;
    }

    // Permanently closes this worker's listener during shutdown.
    void stop_accepting() noexcept {
        if (listen_socket_.fd() < 0) {
            return;
        }
        if (listener_registered_) {
            remove_fd(listen_socket_.fd());
            listener_registered_ = false;
        }
        listen_socket_.reset();
    }

    // Opens the emergency descriptor reserved for recovery from EMFILE.
    static UniqueFd open_reserve_fd() {
        const int fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            throw std::runtime_error(std::string("open(/dev/null) failed: ") + std::strerror(errno));
        }
        return UniqueFd(fd);
    }

    // Frees the reserve descriptor, accepts and rejects one queued client, then
    // restores the reserve so future descriptor exhaustion remains recoverable.
    void recover_from_emfile() noexcept {
        reserve_fd_.reset();
        sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        UniqueFd rejected_client(::accept4(listen_socket_.fd(),
                                           reinterpret_cast<sockaddr*>(&client_addr),
                                           &client_addr_len,
                                           SOCK_NONBLOCK | SOCK_CLOEXEC));
        if (rejected_client) {
            ++stats_.rejected;
        }
        try {
            reserve_fd_ = open_reserve_fd();
        } catch (const std::exception& ex) {
            std::cerr << name_ << " cannot restore emergency file descriptor: " << ex.what()
                      << std::endl;
        }
    }

    static std::uint64_t current_tick() noexcept {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    [[nodiscard]] std::uint32_t next_connection_generation() noexcept {
        const std::uint32_t result = next_generation_;
        ++next_generation_;
        if (next_generation_ == 0) {
            next_generation_ = 1;
        }
        return result;
    }

    // Removes a connection from its intrusive timing-wheel list in O(1).
    void unschedule_timeout(ConnectionState& connection) noexcept {
        if (!connection.wheel_scheduled) {
            return;
        }
        if (connection.wheel_previous >= 0) {
            ConnectionState* previous = connections_.find(connection.wheel_previous);
            if (previous != nullptr) {
                previous->wheel_next = connection.wheel_next;
            }
        } else {
            timing_wheel_[connection.wheel_slot] = connection.wheel_next;
        }
        if (connection.wheel_next >= 0) {
            ConnectionState* next = connections_.find(connection.wheel_next);
            if (next != nullptr) {
                next->wheel_previous = connection.wheel_previous;
            }
        }
        connection.wheel_previous = -1;
        connection.wheel_next = -1;
        connection.wheel_scheduled = false;
    }

    // Tracks the earliest inactivity or absolute protocol-progress deadline.
    void schedule_timeout(ConnectionState& connection) noexcept {
        unschedule_timeout(connection);
        connection.expiration_tick = connection.idle_deadline_tick;
        if (connection.request_deadline_tick != 0) {
            connection.expiration_tick = std::min(connection.expiration_tick,
                                                  connection.request_deadline_tick);
        }
        if (connection.response_deadline_tick != 0) {
            connection.expiration_tick = std::min(connection.expiration_tick,
                                                  connection.response_deadline_tick);
        }
        if (connection.tls_handshake_deadline_tick != 0) {
            connection.expiration_tick = std::min(connection.expiration_tick,
                                                  connection.tls_handshake_deadline_tick);
        }
        connection.wheel_slot = static_cast<std::uint8_t>(
            connection.expiration_tick % kTimingWheelSlots);
        connection.wheel_next = timing_wheel_[connection.wheel_slot];
        if (connection.wheel_next >= 0) {
            ConnectionState* next = connections_.find(connection.wheel_next);
            if (next != nullptr) {
                next->wheel_previous = connection.fd();
            }
        }
        timing_wheel_[connection.wheel_slot] = connection.fd();
        connection.wheel_scheduled = true;
    }

    void touch(ConnectionState& connection) noexcept {
        connection.idle_deadline_tick = current_tick() +
            static_cast<std::uint64_t>(idle_timeout_.count()) + 1U;
        schedule_timeout(connection);
    }

    bool advance_tls_handshake(ConnectionState& connection) noexcept {
        if (connection.tls == nullptr || connection.tls_established) {
            return true;
        }
        const secure_transport::IoStatus status = connection.tls->handshake();
        switch (status) {
        case secure_transport::IoStatus::Complete:
            try {
                if (connection.tls->session_reused() ||
                    !connection.tls->peer_verified() ||
                    !connection.tls->peer_authorized()) {
                    log_tls_error(
                        "rejected resumed, unverified, or unauthorized TLS peer",
                        connection.fd());
                    return false;
                }
            } catch (...) {
                log_tls_error("rejected unverified or unauthorized TLS peer", connection.fd());
                return false;
            }
            if (connection.tls_handshake_counted) {
                --active_tls_handshakes_;
                connection.tls_handshake_counted = false;
            }
            ++stats_.tls_handshakes_succeeded;
            connection.tls_established = true;
            connection.tls_wants_write = false;
            connection.tls_retry_operation = TlsRetryOperation::None;
            connection.tls_handshake_deadline_tick = 0;
            touch(connection);
            return true;
        case secure_transport::IoStatus::WantRead:
            connection.tls_wants_write = false;
            return true;
        case secure_transport::IoStatus::WantWrite:
            connection.tls_wants_write = true;
            return true;
        case secure_transport::IoStatus::PeerClosed:
            return false;
        case secure_transport::IoStatus::Fatal:
            log_tls_error(connection.tls->last_error(), connection.fd());
            return false;
        }
        return false;
    }

    void log_tls_error(const std::string& message, int fd) noexcept {
        if (tls_error_logs_ < kMaxTlsErrorLogsPerLoop) {
            ++tls_error_logs_;
            std::cerr << name_ << ' ' << message << " on fd " << fd << '\n';
            if (tls_error_logs_ == kMaxTlsErrorLogsPerLoop) {
                std::cerr << name_ << " suppressing further per-connection TLS errors\n";
            }
        }
    }

    void log_protocol_error(const char* message, int fd) noexcept {
        if (protocol_error_logs_ < kMaxTlsErrorLogsPerLoop) {
            ++protocol_error_logs_;
            std::cerr << name_ << " protocol exception on fd " << fd
                      << ": " << message << '\n';
            if (protocol_error_logs_ == kMaxTlsErrorLogsPerLoop) {
                std::cerr << name_ << " suppressing further protocol exception logs\n";
            }
        }
    }

    [[nodiscard]] bool defer_buffered_tls_read(ConnectionState& connection) noexcept {
        if (connection.buffered_tls_read_queued) {
            return true;
        }
        try {
            buffered_tls_reads_.push_back(epoll_runtime::ConnectionId{
                .descriptor = static_cast<std::uint32_t>(connection.fd()),
                .generation = connection.generation});
            connection.buffered_tls_read_queued = true;
            return true;
        } catch (...) {
            return false;
        }
    }

    // OpenSSL can retain decrypted bytes after the kernel socket is drained.
    // Such bytes cannot generate another EPOLLIN notification, so process a
    // bounded number of synthetic read-ready events before the next epoll wait.
    void process_buffered_tls_reads() {
        const std::size_t count = std::min(
            buffered_tls_reads_.size(), kMaxDeferredTlsReadsPerIteration);
        for (std::size_t index = 0; index < count; ++index) {
            const epoll_runtime::ConnectionId id = buffered_tls_reads_.front();
            buffered_tls_reads_.pop_front();
            const int fd = static_cast<int>(id.descriptor);
            ConnectionState* connection = connections_.find(fd);
            if (connection == nullptr || connection->generation != id.generation) {
                continue;
            }
            connection->buffered_tls_read_queued = false;
            epoll_event event{};
            event.events = EPOLLIN;
            event.data.u64 = epoll_runtime::encode(id);
            handle_event(event);
        }
    }

    // Routes one epoll event to wake, accept, read, write, error, or hangup logic.
    void handle_event(const epoll_event& event) {
        const epoll_runtime::ConnectionId event_id = epoll_runtime::decode(event.data.u64);
        const int event_fd = static_cast<int>(event_id.descriptor);
        if (event_id.generation == 0 && event_fd == wake_fd_.fd()) {
            drain_wake_fd();
            return;
        }

        if (event_id.generation == 0 && event_fd == listen_socket_.fd()) {
            accept_ready_connections();
            return;
        }

        ConnectionState* connection = connections_.find(event_fd);
        if (connection == nullptr || connection->generation != event_id.generation) {
            return;
        }

        if ((event.events & EPOLLERR) != 0U) {
            int socket_error = 0;
            socklen_t length = sizeof(socket_error);
            if (::getsockopt(connection->fd(), SOL_SOCKET, SO_ERROR,
                             &socket_error, &length) == 0 && socket_error != 0) {
                std::cerr << name_ << " socket error on fd " << connection->fd()
                          << ": " << std::strerror(socket_error) << std::endl;
            }
            close_connection(connection->fd());
            return;
        }

        const bool full_hangup = (event.events & EPOLLHUP) != 0U;
        if ((event.events & EPOLLRDHUP) != 0U) {
            connection->peer_write_closed = true;
        }
        if (!connection->tls_established) {
            if (!advance_tls_handshake(*connection)) {
                close_connection(event_fd);
                return;
            }
            if (!connection->tls_established) {
                if (!update_connection_interest(*connection)) {
                    close_connection(event_fd);
                }
                return;
            }
        }
        bool keep_open = true;
        const bool retrying_tls_write =
            connection->tls_retry_operation == TlsRetryOperation::Write;
        const bool read_ready = connection->tls_wants_write
            ? (event.events & EPOLLOUT) != 0U
            : (event.events & EPOLLIN) != 0U;
        if (!retrying_tls_write && read_ready) {
            keep_open = handle_read(*connection);
            connection = connections_.find(event_fd);
        }

        if (!keep_open || connection == nullptr) {
            close_connection(event_fd);
            return;
        }

        const bool write_ready = connection->tls_wants_write
            ? (event.events & EPOLLOUT) != 0U
            : (event.events & EPOLLIN) != 0U || (event.events & EPOLLOUT) != 0U;
        if (connection->has_responses() && write_ready &&
            connection->tls_retry_operation != TlsRetryOperation::Read) {
            keep_open = handle_write(*connection);
        }

        connection = connections_.find(event_fd);
        if (!keep_open || connection == nullptr) {
            close_connection(event_fd);
            return;
        }

        if (full_hangup || (connection->peer_write_closed && !connection->has_responses())) {
            close_connection(event_fd);
            return;
        }

        if (!update_connection_interest(*connection)) {
            close_connection(event_fd);
        }
    }

    // Uses level-triggered readiness so bounded per-event work remains fair and
    // any unread/unwritten data is reported again without relying on ET sizing.
    bool update_connection_interest(ConnectionState& connection) noexcept {
        std::uint32_t events = EPOLLRDHUP | EPOLLERR;
        if (!connection.tls_established) {
            events |= connection.tls_wants_write ? EPOLLOUT : EPOLLIN;
        } else {
            if (!connection.peer_write_closed) {
                events |= EPOLLIN;
            }
            if (connection.has_responses() || connection.tls_wants_write) {
                events |= EPOLLOUT;
            }
        }
        if (events == connection.registered_events) {
            return true;
        }
        if (!try_modify_fd(connection.fd(), connection.generation, events)) {
            return false;
        }
        connection.registered_events = events;
        return true;
    }

    // Accepts a bounded batch from the ready listener, registers each client,
    // and applies backpressure at resource or connection limits.
    void accept_ready_connections() {
        if (connections_.size() >= max_connections_) {
            pause_accepting(kAcceptCapacityBackoff);
            return;
        }
        if (transport_mode_ == secure_transport::Mode::Tls &&
            active_tls_handshakes_ >=
                std::min(max_connections_, kMaxTlsHandshakesPerLoop)) {
            ++stats_.tls_handshakes_rejected_capacity;
            pause_accepting(kAcceptCapacityBackoff);
            return;
        }

        for (std::size_t accepted = 0; accepted < kAcceptBatchSize; ++accepted) {
            sockaddr_in client_addr{};
            socklen_t client_addr_len = sizeof(client_addr);
            UniqueFd client_socket(::accept4(
                listen_socket_.fd(),
                reinterpret_cast<sockaddr*>(&client_addr),
                &client_addr_len,
                SOCK_NONBLOCK | SOCK_CLOEXEC));

            if (!client_socket) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                if (is_resource_exhaustion_error(errno)) {
                    std::cerr << name_ << " accept resource exhaustion: " << std::strerror(errno)
                              << std::endl;
                    if (errno == EMFILE) {
                        recover_from_emfile();
                    }
                    pause_accepting(kAcceptResourceBackoff);
                    return;
                }
                throw std::runtime_error(std::string("accept4 failed: ") + std::strerror(errno));
            }

            if (connections_.size() >= max_connections_) {
                ++stats_.rejected;
                pause_accepting(kAcceptCapacityBackoff);
                return;
            }

            const int client_fd = client_socket.get();
            bool connection_created = false;
            try {
                configure_client_socket(client_fd);
                const std::uint32_t generation = next_connection_generation();
                ConnectionState& connection =
                    connections_.emplace(std::move(client_socket), generation, transport_mode_,
                                         tls_contexts_ ? tls_contexts_->load() : nullptr,
                                         *protocol_factory_);
                connection_created = true;

                if (!connection.tls_established) {
                    ++active_tls_handshakes_;
                    connection.tls_handshake_counted = true;
                    connection.tls_handshake_deadline_tick = current_tick() +
                        static_cast<std::uint64_t>(kTlsHandshakeTimeout.count()) + 1U;
                }

                // Register the socket before publishing its idle deadline.  If epoll
                // registration fails, the whole connection transaction is rolled back.
                constexpr std::uint32_t initial_events =
                    EPOLLIN | EPOLLRDHUP | EPOLLERR;
                if (!try_register_connection_fd(client_fd, generation, initial_events)) {
                    connections_.erase(client_fd);
                    continue;
                }
                connection.registered_events = initial_events;

                touch(connection);
                ++stats_.accepted;
            } catch (const std::bad_alloc&) {
                if (connection_created) {
                    remove_fd(client_fd);
                    connections_.erase(client_fd);
                }
                std::cerr << name_ << " unable to allocate connection state for fd "
                          << client_fd << std::endl;
                continue;
            } catch (const std::exception& ex) {
                if (connection_created) {
                    remove_fd(client_fd);
                    connections_.erase(client_fd);
                }
                std::cerr << name_ << " failed to initialize fd " << client_fd
                          << ": " << ex.what() << std::endl;
                continue;
            } catch (...) {
                if (connection_created) {
                    remove_fd(client_fd);
                    connections_.erase(client_fd);
                }
                std::cerr << name_ << " failed to initialize fd " << client_fd
                          << ": unknown exception" << std::endl;
                continue;
            }
        }
    }

    // Reads bounded newline-delimited requests. Multiple lines may be queued on
    // one keep-alive connection; the fixed response ring bounds memory usage.
    bool handle_read(ConnectionState& connection) {
        std::array<char, 512> buffer{};
        std::size_t bytes_read = 0;

        while (bytes_read < kMaxReadBytesPerEvent) {
            const std::size_t read_size = std::min(buffer.size(), kMaxReadBytesPerEvent - bytes_read);
            ssize_t n = 0;
            if (connection.tls) {
                const auto result = connection.tls->read(std::span<std::byte>(
                    reinterpret_cast<std::byte*>(buffer.data()), read_size));
                if (result.status == secure_transport::IoStatus::WantRead) {
                    connection.tls_wants_write = false;
                    connection.tls_retry_operation = TlsRetryOperation::None;
                    return true;
                }
                if (result.status == secure_transport::IoStatus::WantWrite) {
                    connection.tls_wants_write = true;
                    connection.tls_retry_operation = TlsRetryOperation::Read;
                    return true;
                }
                if (result.status == secure_transport::IoStatus::PeerClosed) {
                    connection.peer_write_closed = true;
                    return true;
                }
                if (result.status == secure_transport::IoStatus::Fatal) {
                    return false;
                }
                connection.tls_wants_write = false;
                connection.tls_retry_operation = TlsRetryOperation::None;
                n = static_cast<ssize_t>(result.bytes);
            } else {
                n = ::recv(connection.fd(), buffer.data(), read_size, 0);
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return true;
                    }
                    return false;
                }
                if (n == 0) {
                    connection.peer_write_closed = true;
                    return true;
                }
            }

            const std::size_t chunk_size = static_cast<std::size_t>(n);
            bytes_read += chunk_size;
            const bool had_output = connection.protocol->has_output();
            try {
                if (!connection.protocol->consume(std::span<const std::byte>(
                        reinterpret_cast<const std::byte*>(buffer.data()), chunk_size))) {
                    return false;
                }
            } catch (const std::exception& error) {
                ++stats_.protocol_exceptions;
                log_protocol_error(error.what(), connection.fd());
                return false;
            } catch (...) {
                ++stats_.protocol_exceptions;
                log_protocol_error("unknown exception", connection.fd());
                return false;
            }
            if (connection.protocol->has_partial_input()) {
                if (connection.request_deadline_tick == 0) {
                    connection.request_deadline_tick = current_tick() +
                        static_cast<std::uint64_t>(kRequestCompletionTimeout.count()) + 1U;
                }
            } else {
                connection.request_deadline_tick = 0;
            }
            if (!had_output && connection.protocol->has_output()) {
                connection.response_deadline_tick = current_tick() +
                    static_cast<std::uint64_t>(kResponseDrainTimeout.count()) + 1U;
            }
            touch(connection);
        }
        return connection.tls == nullptr || !connection.tls->has_buffered_plaintext() ||
               defer_buffered_tls_read(connection);
    }

    // Sends queued responses in request order while bounding work per event.
    bool handle_write(ConnectionState& connection) {
        std::size_t bytes_written = 0;
        while (connection.has_responses() && bytes_written < kMaxWriteBytesPerEvent) {
            const std::size_t budget = kMaxWriteBytesPerEvent - bytes_written;
            const server_runtime::OutputBatch output = connection.protocol->output();
            if (output.count == 0 || output.count > output.slices.size()) {
                return false;
            }
            if (output.lifetime) {
                connection.output_lifetime = output.lifetime;
            }

            // Plain TCP uses both slices directly with sendmsg. TLS has no writev
            // API, so multiple slices are copied into lazy per-connection storage
            // and encrypted with one SSL_write_ex call. That storage is retained
            // unchanged if OpenSSL asks us to retry the write.
            std::array<iovec, 2> vectors{};
            int vector_count = 0;
            std::size_t remaining_budget = budget;
            for (std::size_t i = 0; i < output.count && remaining_budget != 0; ++i) {
                const std::size_t slice_size =
                    std::min(output.slices[i].size(), remaining_budget);
                if (slice_size == 0) {
                    continue;
                }
                vectors[static_cast<std::size_t>(vector_count++)] = iovec{
                    .iov_base = const_cast<std::byte*>(output.slices[i].data()),
                    .iov_len = slice_size};
                remaining_budget -= slice_size;
            }
            if (vector_count == 0) {
                return false;
            }

            msghdr message{};
            message.msg_iov = vectors.data();
            message.msg_iovlen = static_cast<std::size_t>(vector_count);
            ssize_t n = 0;
            if (connection.tls) {
                std::span<const std::byte> tls_input;
                if (connection.tls_coalesced_write != nullptr &&
                    !connection.tls_coalesced_write->bytes.empty()) {
                    tls_input = connection.tls_coalesced_write->bytes;
                } else if (vector_count > 1) {
                    try {
                        if (connection.tls_coalesced_write == nullptr) {
                            connection.tls_coalesced_write =
                                std::make_unique<TlsCoalescedWrite>();
                            connection.tls_coalesced_write->bytes.reserve(
                                sizeof(std::uint32_t) + tcp_common::kMaxPayloadSize);
                        }
                        auto& combined = connection.tls_coalesced_write->bytes;
                        std::size_t combined_size = 0;
                        for (int i = 0; i < vector_count; ++i) {
                            combined_size += vectors[static_cast<std::size_t>(i)].iov_len;
                        }
                        combined.resize(combined_size);
                        std::size_t offset = 0;
                        for (int i = 0; i < vector_count; ++i) {
                            const iovec& vector = vectors[static_cast<std::size_t>(i)];
                            std::memcpy(combined.data() + offset,
                                        vector.iov_base,
                                        vector.iov_len);
                            offset += vector.iov_len;
                        }
                        tls_input = combined;
                    } catch (const std::bad_alloc&) {
                        return false;
                    }
                } else {
                    tls_input = std::span<const std::byte>(
                        static_cast<const std::byte*>(vectors[0].iov_base),
                        vectors[0].iov_len);
                }
                const bool used_coalesced_buffer =
                    connection.tls_coalesced_write != nullptr &&
                    !connection.tls_coalesced_write->bytes.empty();
                const auto result = connection.tls->write(tls_input);
                if (result.status == secure_transport::IoStatus::WantRead) {
                    connection.tls_wants_write = false;
                    connection.tls_retry_operation = TlsRetryOperation::Write;
                    return true;
                }
                if (result.status == secure_transport::IoStatus::WantWrite) {
                    connection.tls_wants_write = true;
                    // OpenSSL requires the same SSL_write_ex call to be retried
                    // before any other I/O that could advance this SSL object.
                    connection.tls_retry_operation = TlsRetryOperation::Write;
                    return true;
                }
                if (result.status != secure_transport::IoStatus::Complete) {
                    return false;
                }
                connection.tls_wants_write = false;
                connection.tls_retry_operation = TlsRetryOperation::None;
                n = static_cast<ssize_t>(result.bytes);
                if (used_coalesced_buffer) {
                    connection.tls_coalesced_write->bytes.clear();
                }
            } else {
                n = ::sendmsg(connection.fd(),
                              &message,
                              MSG_NOSIGNAL | MSG_DONTWAIT);
            }
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return true;
                }
                return false;
            }
            if (n == 0) {
                return false;
            }

            const std::size_t sent = static_cast<std::size_t>(n);
            connection.protocol->consume_output(sent);
            bytes_written += sent;
            if (!connection.has_responses()) {
                connection.response_deadline_tick = 0;
                connection.output_lifetime.reset();
            }
            // Progress refreshes inactivity only. The absolute response deadline
            // prevents a slow reader from retaining this connection indefinitely.
            if (!connection.peer_write_closed) {
                touch(connection);
            }
        }

        return true;
    }

    // Advances the one-second timing wheel and closes expired connections.
    void expire_idle_connections() {
        const std::uint64_t now = current_tick();
        while (last_expired_tick_ < now) {
            ++last_expired_tick_;
            const std::size_t slot = static_cast<std::size_t>(
                last_expired_tick_ % kTimingWheelSlots);
            int fd = timing_wheel_[slot];
            while (fd >= 0) {
                ConnectionState* connection = connections_.find(fd);
                if (connection == nullptr) {
                    break;
                }
                const int next_fd = connection->wheel_next;
                if (connection->expiration_tick <= now) {
                    close_connection(fd);
                }
                fd = next_fd;
            }
        }
    }

    // Removes fd from epoll and releases its state, updating close statistics.
    void close_connection(int fd) noexcept {
        ConnectionState* connection = connections_.find(fd);
        if (connection == nullptr) {
            return;
        }

        unschedule_timeout(*connection);
        if (connection->tls_handshake_counted) {
            --active_tls_handshakes_;
            connection->tls_handshake_counted = false;
            ++stats_.tls_handshakes_failed;
        }
        remove_fd(fd);
        if (connection->tls != nullptr && connection->tls_established) {
            (void)connection->tls->shutdown();
        }
        connections_.erase(fd);
        ++stats_.closed;
    }

    // Removes and releases every client owned by this worker during teardown.
    void shutdown_all_connections() noexcept {
        for (auto it = connections_.begin(); it != connections_.end();) {
            const int fd = it->first;
            remove_fd(fd);
            it = connections_.erase(it);
            ++stats_.closed;
        }
    }

    std::size_t loop_id_;
    std::string name_;
    std::chrono::seconds idle_timeout_;
    std::size_t max_connections_;
    secure_transport::Mode transport_mode_;
    std::shared_ptr<secure_transport::TlsContextStore> tls_contexts_;
    std::shared_ptr<const server_runtime::ProtocolFactory> protocol_factory_;
    EventLoopStats stats_;
    UniqueFd epoll_fd_;
    UniqueFd listen_socket_;
    UniqueFd wake_fd_;
    UniqueFd reserve_fd_;
    bool listener_registered_ = false;
    std::chrono::steady_clock::time_point accept_resume_time_{};
    ConnectionTable connections_;
    std::array<int, kTimingWheelSlots> timing_wheel_{};
    std::uint64_t last_expired_tick_ = 0;
    std::size_t active_tls_handshakes_ = 0;
    std::size_t tls_error_logs_ = 0;
    std::size_t protocol_error_logs_ = 0;
    std::uint32_t next_generation_ = 1;
    std::deque<epoll_runtime::ConnectionId> buffered_tls_reads_;
};

// Constructs the public worker facade from its identifier, shared port,
// per-connection idle timeout, and per-worker connection limit.
EventLoop::EventLoop(std::size_t loop_id,
                     int listen_port,
                     std::chrono::seconds idle_timeout,
                     std::size_t max_connections,
                     secure_transport::Mode transport_mode,
                     std::shared_ptr<secure_transport::TlsContextStore> tls_contexts,
                     std::shared_ptr<const server_runtime::ProtocolFactory> protocol_factory)
    : impl_(std::make_unique<Impl>(loop_id, listen_port, idle_timeout, max_connections,
                                   transport_mode, std::move(tls_contexts),
                                   std::move(protocol_factory))) {}

EventLoop::~EventLoop() noexcept = default;

// Delegates event processing to the implementation until stop_token is set.
void EventLoop::run(std::stop_token stop_token) {
    impl_->run(stop_token);
}

// Delegates a thread-safe wake notification to the implementation.
void EventLoop::wake() noexcept {
    impl_->wake();
}

// Returns a snapshot of this worker's lifecycle counters.
EventLoopStats EventLoop::stats() const noexcept {
    return impl_->stats();
}

// Coordinates event_loop_count workers on listen_port, applying idle_timeout
// and max_connections_per_loop; port_instance_lock is retained for exclusivity.
void tcp_server::start_listen(int listen_port,
                  std::size_t event_loop_count,
                  std::chrono::seconds idle_timeout,
                  std::size_t max_connections_per_loop,
                  secure_transport::Mode transport_mode,
                  const secure_transport::ServerTlsConfig& tls_config,
                  const std::string& tls_client_allowlist_file,
                  const std::string& tls_key_passphrase_file,
                  std::shared_ptr<secure_transport::TlsContextStore> tls_contexts,
                  std::shared_ptr<const server_runtime::ProtocolFactory> protocol_factory,
                  UniqueFd port_instance_lock) {
    // Ownership of this descriptor keeps the advisory lock for the full
    // lifetime of the listening server.
    (void)port_instance_lock;
    g_shutdown_state.store(ShutdownState::Running, std::memory_order_release);
    g_drain_deadline_ns.store(0, std::memory_order_release);
    SignalFd termination_signals;
    UniqueFd worker_completion = create_event_handle();
    std::cout << "Listening on port " << listen_port
              << " transport=" << secure_transport::mode_name(transport_mode)
              << " using " << event_loop_count
              << " epoll event loop(s) with SO_REUSEPORT; maximum active connections: "
              << (event_loop_count * max_connections_per_loop) << std::endl;
    if (transport_mode == secure_transport::Mode::Tls) {
        std::cout << "TLS policy="
                  << secure_transport::tls_version_policy_name(tls_config.version_policy)
                  << " mTLS=required session_resumption=disabled early_data=disabled library="
                  << secure_transport::runtime_version() << '\n';
    }

    // Construct every event loop before starting threads. Listener or epoll
    // creation failures therefore cannot leave a partially running server.
    std::vector<std::unique_ptr<EventLoop>> event_loops;
    event_loops.reserve(event_loop_count);
    for (std::size_t i = 0; i < event_loop_count; ++i) {
        event_loops.push_back(std::make_unique<EventLoop>(
            i + 1, listen_port, idle_timeout, max_connections_per_loop,
            transport_mode, tls_contexts, protocol_factory));
    }

    const auto wake_all = [&event_loops]() noexcept {
        for (const auto& event_loop : event_loops) {
            event_loop->wake();
        }
    };

    std::exception_ptr worker_exception;
    std::mutex worker_exception_mutex;
    std::vector<std::jthread> workers;
    workers.reserve(event_loop_count);

    const auto stop_and_join = [&]() noexcept {
        g_shutdown_state.store(ShutdownState::Stopping, std::memory_order_release);
        for (auto& worker : workers) {
            worker.request_stop();
        }
        wake_all();
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    };

    try {
        for (std::size_t i = 0; i < event_loop_count; ++i) {
            workers.emplace_back([&, i](std::stop_token stop_token) {
                try {
                    pin_current_thread(i);
                    event_loops[i]->run(stop_token);
                } catch (...) {
                    {
                        std::lock_guard lock(worker_exception_mutex);
                        if (!worker_exception) {
                            worker_exception = std::current_exception();
                        }
                    }
                    g_shutdown_state.store(ShutdownState::Stopping, std::memory_order_release);
                    wake_all();
                }

                const std::uint64_t one = 1;
                for (;;) {
                    const ssize_t result =
                        ::write(worker_completion.fd(), &one, sizeof(one));
                    if (result == static_cast<ssize_t>(sizeof(one))) {
                        break;
                    }
                    if (result < 0 && errno == EINTR) {
                        continue;
                    }
                    break;
                }
            });
        }
    } catch (...) {
        stop_and_join();
        throw;
    }

    int last_termination_signal = 0;
    std::size_t remaining_workers = workers.size();

    try {
        while (remaining_workers != 0) {
            if (g_shutdown_state.load(std::memory_order_acquire) ==
                    ShutdownState::Draining &&
                steady_clock_ns() >=
                    g_drain_deadline_ns.load(std::memory_order_acquire)) {
                g_shutdown_state.store(ShutdownState::Stopping,
                                       std::memory_order_release);
                wake_all();
            }

            std::array<pollfd, 2> poll_fds{{
                {termination_signals.fd(), POLLIN, 0},
                {worker_completion.fd(), POLLIN, 0},
            }};
            const int ready = ::poll(poll_fds.data(), poll_fds.size(), 250);
            if (ready < 0) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::runtime_error(std::string("coordinator poll failed: ") +
                                         std::strerror(errno));
            }

            for (const pollfd& descriptor : poll_fds) {
                if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    throw std::runtime_error("coordinator descriptor became invalid");
                }
            }

            if ((poll_fds[0].revents & POLLIN) != 0) {
                for (;;) {
                    signalfd_siginfo signal_info{};
                    const ssize_t count = ::read(termination_signals.fd(),
                                                 &signal_info,
                                                 sizeof(signal_info));
                    if (count == static_cast<ssize_t>(sizeof(signal_info))) {
                        if (signal_info.ssi_signo == SIGHUP) {
                            if (transport_mode == secure_transport::Mode::Tls && tls_contexts) {
                                try {
                                    secure_transport::ServerTlsConfig reload_config = tls_config;
                                    reload_config.allow_interactive_private_key_prompt = false;
                                    if (!tls_key_passphrase_file.empty()) {
                                        reload_config.private_key_passphrase =
                                            secure_transport::load_private_key_passphrase_file(
                                                tls_key_passphrase_file);
                                    }
                                    reload_config.allowed_client_sans =
                                        tcp_server::load_tls_client_allowlist(tls_client_allowlist_file);
                                    auto replacement =
                                        secure_transport::TlsContext::make_server(reload_config);
                                    tls_contexts->store(std::move(replacement));
                                    std::cout << "Reloaded TLS certificate, key, CA, CRL, and "
                                                 "client authorization policy\n";
                                } catch (const std::exception& error) {
                                    std::cerr << "TLS reload failed; retaining previous context: "
                                              << error.what() << '\n';
                                }
                            }
                            continue;
                        }
                        last_termination_signal =
                            static_cast<int>(signal_info.ssi_signo);
                        begin_graceful_shutdown();
                        wake_all();
                        continue;
                    }
                    if (count < 0 && errno == EINTR) {
                        continue;
                    }
                    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    }
                    throw std::runtime_error("short or failed read from signalfd");
                }
            }

            if ((poll_fds[1].revents & POLLIN) != 0) {
                for (;;) {
                    std::uint64_t completed = 0;
                    const ssize_t count = ::read(worker_completion.fd(),
                                                 &completed,
                                                 sizeof(completed));
                    if (count == static_cast<ssize_t>(sizeof(completed))) {
                        const std::size_t completed_count =
                            completed > remaining_workers
                                ? remaining_workers
                                : static_cast<std::size_t>(completed);
                        remaining_workers -= completed_count;
                        continue;
                    }
                    if (count < 0 && errno == EINTR) {
                        continue;
                    }
                    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    }
                    throw std::runtime_error("short or failed read from worker eventfd");
                }
            }
        }
    } catch (...) {
        stop_and_join();
        throw;
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    if (worker_exception) {
        try {
            std::rethrow_exception(worker_exception);
        } catch (const std::exception& ex) {
            throw std::runtime_error(std::string("event-loop worker failed: ") + ex.what());
        } catch (...) {
            throw std::runtime_error("event-loop worker failed with an unknown exception");
        }
    }

    EventLoopStats totals;
    for (const auto& event_loop : event_loops) {
        const EventLoopStats loop_stats = event_loop->stats();
        totals.accepted += loop_stats.accepted;
        totals.rejected += loop_stats.rejected;
        totals.closed += loop_stats.closed;
        totals.tls_handshakes_succeeded += loop_stats.tls_handshakes_succeeded;
        totals.tls_handshakes_failed += loop_stats.tls_handshakes_failed;
        totals.tls_handshakes_rejected_capacity +=
            loop_stats.tls_handshakes_rejected_capacity;
        totals.protocol_exceptions += loop_stats.protocol_exceptions;
    }

    std::cout << "Shutdown"
              << (last_termination_signal == 0
                      ? " completed"
                      : " completed after signal " +
                            std::to_string(last_termination_signal))
              << ". accepted=" << totals.accepted
              << " rejected=" << totals.rejected
              << " closed=" << totals.closed
              << " tls_handshakes_succeeded=" << totals.tls_handshakes_succeeded
              << " tls_handshakes_failed=" << totals.tls_handshakes_failed
              << " tls_handshakes_rejected_capacity="
              << totals.tls_handshakes_rejected_capacity
              << " protocol_exceptions=" << totals.protocol_exceptions << std::endl;
}

// Parses server and mapping options, initializes the shared request mapping,
// optionally exports keys, and starts listeners. argc/argv are the CLI inputs.
