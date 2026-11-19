// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.

#include "tcp/mapping_protocol.h"

#include <algorithm>
#include <cstring>
#include <new>

namespace {
constexpr std::size_t kMaxRequestSize = 1024;
constexpr std::size_t kMaxPipelinedResponses = 16;
}

// Stores overflow responses only when the current response slot is occupied.
struct MappingProtocolConnection::PipelinedResponseOverflow {
    static constexpr std::size_t kCapacity = kMaxPipelinedResponses - 1;
    std::array<ResponseBufferView, kCapacity> responses{};
    std::size_t head = 0;
    std::size_t count = 0;
};

MappingProtocolConnection::~MappingProtocolConnection() = default;

// Consumes fragmented or pipelined newline-delimited request keys.
bool MappingProtocolConnection::consume(std::span<const std::byte> input) {
    const char* chunk = reinterpret_cast<const char*>(input.data());
    std::size_t consumed = 0;
    while (consumed < input.size()) {
        const void* newline_ptr =
            std::memchr(chunk + consumed, '\n', input.size() - consumed);
        const std::size_t fragment_size = newline_ptr == nullptr
            ? input.size() - consumed
            : static_cast<std::size_t>(static_cast<const char*>(newline_ptr) -
                                       (chunk + consumed));
        if (fragment_size > kMaxRequestSize - request_line_.size()) {
            return false;
        }
        request_line_.append(chunk + consumed, fragment_size);
        consumed += fragment_size;
        if (newline_ptr == nullptr) {
            break;
        }
        ++consumed;
        if (!request_line_.empty() && request_line_.back() == '\r') {
            request_line_.pop_back();
        }
        if (request_line_.empty() || response_queue_full()) {
            return false;
        }
        const std::optional<ResponseBufferView> response =
            find_client_response(request_line_);
        if (!response.has_value() || !push_response(*response)) {
            return false;
        }
        request_line_.clear();
    }
    return true;
}

// Reports whether an incomplete request line is buffered.
bool MappingProtocolConnection::has_partial_input() const noexcept {
    return !request_line_.empty();
}

// Reports whether a response is ready to be written.
bool MappingProtocolConnection::has_output() const noexcept {
    return response_.size != 0;
}

// Exposes the remaining response prefix and payload as separate slices.
server_runtime::OutputBatch MappingProtocolConnection::output() const noexcept {
    server_runtime::OutputBatch batch;
    if (!has_output()) {
        return batch;
    }
    const std::size_t header_remaining = response_header_.size() - response_header_sent_;
    if (header_remaining != 0) {
        batch.slices[batch.count++] = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(response_header_.data() +
                                               response_header_sent_),
            header_remaining);
    }
    const std::size_t payload_remaining = response_.size - response_sent_;
    if (payload_remaining != 0) {
        batch.slices[batch.count++] = std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(response_.data + response_sent_),
            payload_remaining);
    }
    return batch;
}

// Advances the response cursor and releases the current slot when fully sent.
void MappingProtocolConnection::consume_output(std::size_t bytes) noexcept {
    const std::size_t header_remaining = response_header_.size() - response_header_sent_;
    const std::size_t header_bytes = std::min(bytes, header_remaining);
    response_header_sent_ += header_bytes;
    response_sent_ += bytes - header_bytes;
    if (response_header_sent_ == response_header_.size() &&
        response_sent_ == response_.size) {
        pop_response();
    }
}

// Detects when the fixed response ring cannot accept another pipelined result.
bool MappingProtocolConnection::response_queue_full() const noexcept {
    return has_output() && response_overflow_ != nullptr &&
           response_overflow_->count == PipelinedResponseOverflow::kCapacity;
}

// Initializes the four-byte network-order response prefix and payload cursor.
void MappingProtocolConnection::set_current_response(
    ResponseBufferView next_response) noexcept {
    response_ = next_response;
    const auto size = static_cast<std::uint32_t>(next_response.size);
    response_header_ = {
        static_cast<std::uint8_t>(size >> 24U),
        static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U),
        static_cast<std::uint8_t>(size)};
    response_header_sent_ = 0;
    response_sent_ = 0;
}

// Queues a response in the current slot or bounded overflow ring.
bool MappingProtocolConnection::push_response(
    ResponseBufferView next_response) noexcept {
    if (!has_output()) [[likely]] {
        set_current_response(next_response);
        return true;
    }
    if (response_overflow_ == nullptr) {
        try {
            response_overflow_ = std::make_unique<PipelinedResponseOverflow>();
        } catch (const std::bad_alloc&) {
            return false;
        }
    }
    if (response_overflow_->count == PipelinedResponseOverflow::kCapacity) {
        return false;
    }
    const std::size_t tail =
        (response_overflow_->head + response_overflow_->count) %
        PipelinedResponseOverflow::kCapacity;
    response_overflow_->responses[tail] = next_response;
    ++response_overflow_->count;
    return true;
}

// Promotes the next queued response or clears the completed response state.
void MappingProtocolConnection::pop_response() noexcept {
    if (response_overflow_ == nullptr || response_overflow_->count == 0) [[likely]] {
        response_ = {};
        response_header_sent_ = 0;
        response_sent_ = 0;
        response_overflow_.reset();
        return;
    }
    const ResponseBufferView next_response =
        response_overflow_->responses[response_overflow_->head];
    response_overflow_->head =
        (response_overflow_->head + 1) % PipelinedResponseOverflow::kCapacity;
    --response_overflow_->count;
    if (response_overflow_->count == 0) {
        response_overflow_.reset();
    }
    set_current_response(next_response);
}

// Creates a fresh protocol state object for a newly accepted connection.
std::unique_ptr<server_runtime::ProtocolConnection>
MappingProtocolFactory::create() const {
    return std::make_unique<MappingProtocolConnection>();
}
