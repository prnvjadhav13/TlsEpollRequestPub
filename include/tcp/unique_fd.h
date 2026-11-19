// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.
#pragma once

// Move-only RAII owner for a Linux file descriptor.
class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept;
    ~UniqueFd() noexcept;

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept;
    UniqueFd& operator=(UniqueFd&& other) noexcept;

    [[nodiscard]] int get() const noexcept;
    [[nodiscard]] int fd() const noexcept;
    [[nodiscard]] explicit operator bool() const noexcept;
    [[nodiscard]] int release() noexcept;
    int close() noexcept;
    void reset(int replacement = -1) noexcept;

private:
    int fd_ = -1;
};
