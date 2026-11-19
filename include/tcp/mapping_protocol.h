// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string>

#include "epoll_runtime/protocol.h"
#include "tcp/mapping_store.h"

// Parses newline-delimited mapping keys and queues their binary responses.
class MappingProtocolConnection final : public server_runtime::ProtocolConnection {
public:
    MappingProtocolConnection() = default;
    ~MappingProtocolConnection() override;

    [[nodiscard]] bool consume(std::span<const std::byte> input) override;
    [[nodiscard]] bool has_partial_input() const noexcept override;
    [[nodiscard]] bool has_output() const noexcept override;
    [[nodiscard]] server_runtime::OutputBatch output() const noexcept override;
    void consume_output(std::size_t bytes) noexcept override;

private:
    struct PipelinedResponseOverflow;

    [[nodiscard]] bool response_queue_full() const noexcept;
    void set_current_response(ResponseBufferView next_response) noexcept;
    [[nodiscard]] bool push_response(ResponseBufferView next_response) noexcept;
    void pop_response() noexcept;

    std::string request_line_;
    ResponseBufferView response_{};
    std::array<std::uint8_t, sizeof(std::uint32_t)> response_header_{};
    std::unique_ptr<PipelinedResponseOverflow> response_overflow_;
    std::size_t response_header_sent_ = 0;
    std::size_t response_sent_ = 0;
};

// Creates one mapping protocol connection for each accepted client.
class MappingProtocolFactory final : public server_runtime::ProtocolFactory {
public:
    [[nodiscard]] std::unique_ptr<server_runtime::ProtocolConnection> create() const override;
};
