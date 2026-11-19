// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

inline constexpr std::size_t kDefaultMappingEntries = 500000;

// Selects how mapping payloads are loaded and retained by the server.
enum class MappingLoadMode {
    Ifstream,
    MMap,
    MMapView
};

// Non-owning byte range returned by a mapping lookup. The mapping store keeps
// the referenced payload alive for the server lifetime.
struct ResponseBufferView {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
};

// Loads or generates the process-wide request mapping.
void initialize_request_mapping(const std::string& path,
                                bool force_regenerate,
                                MappingLoadMode load_mode,
                                std::size_t mapping_entries);

// Writes up to max_keys request keys from the active mapping.
void print_request_keys(std::size_t max_keys, const std::string& output_path);

// Looks up request without allocating and returns a borrowed payload view.
std::optional<ResponseBufferView> find_client_response(std::string_view request);
