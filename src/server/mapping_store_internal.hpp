// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include "tcp/mapping_store.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <boost/unordered/unordered_flat_map.hpp>

// Owns generated response bytes in the in-memory mapping representation.
struct ClientResponse {
    std::vector<std::uint8_t> payload;
};

// Hashes owned and borrowed request keys with one process-random SipHash key.
struct TransparentStringHash {
    using is_transparent = void;

    static const std::array<std::uint64_t, 2>& secrets();
    static void sip_round(std::uint64_t& v0, std::uint64_t& v1,
                          std::uint64_t& v2, std::uint64_t& v3) noexcept;
    std::size_t operator()(std::string_view value) const;
    std::size_t operator()(const std::string& value) const;
    std::size_t operator()(const char* value) const;
};

// Compares owned and borrowed string keys without constructing temporary strings.
struct TransparentStringEqual {
    using is_transparent = void;

    bool operator()(std::string_view lhs, std::string_view rhs) const noexcept;
};

using RequestMap = boost::unordered_flat_map<std::string,
                                             ClientResponse,
                                             TransparentStringHash,
                                             TransparentStringEqual>;
using MappedPayloadView = std::span<const std::uint8_t>;
using MappedRequestMap = boost::unordered_flat_map<std::string_view,
                                                   MappedPayloadView,
                                                   TransparentStringHash,
                                                   TransparentStringEqual>;

// Owns an immutable anonymous snapshot of a mapping file.
class MappedRegion {
public:
    MappedRegion(int fd, std::size_t length);
    ~MappedRegion() noexcept;

    MappedRegion(const MappedRegion&) = delete;
    MappedRegion& operator=(const MappedRegion&) = delete;
    MappedRegion(MappedRegion&&) = delete;
    MappedRegion& operator=(MappedRegion&&) = delete;

    [[nodiscard]] const std::uint8_t* data() const noexcept;
    [[nodiscard]] std::size_t size() const noexcept;

private:
    void* addr_ = nullptr;
    std::size_t length_ = 0;
};

// Couples an mmap region with indexes whose keys and payloads borrow from it.
struct MMapViewLoadedData {
    std::unique_ptr<MappedRegion> region;
    MappedRequestMap data;
};

// Stores either owned payloads or mmap-backed views behind a single lookup API.
class MappingStore {
public:
    void set_owned(RequestMap&& data);
    void set_mmap_view(MMapViewLoadedData&& loaded);
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] std::optional<ResponseBufferView> find(
        std::string_view request) const;
    void export_request_keys(std::size_t max_keys,
                             const std::string& output_path) const;

private:
    RequestMap owned_data_;
    std::unique_ptr<MappedRegion> mapped_region_;
    MappedRequestMap mapped_view_data_;
};
