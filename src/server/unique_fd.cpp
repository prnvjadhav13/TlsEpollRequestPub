// Copyright (c) 2026 Ahmad Jadhav. All rights reserved.

#include "tcp/unique_fd.h"

#include <unistd.h>
#include <utility>

UniqueFd::UniqueFd(int fd) noexcept : fd_(fd) {}

UniqueFd::~UniqueFd() noexcept {
    reset();
}

UniqueFd::UniqueFd(UniqueFd&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)) {}

UniqueFd& UniqueFd::operator=(UniqueFd&& other) noexcept {
    if (this != &other) {
        reset(std::exchange(other.fd_, -1));
    }
    return *this;
}

int UniqueFd::get() const noexcept {
    return fd_;
}

int UniqueFd::fd() const noexcept {
    return get();
}

UniqueFd::operator bool() const noexcept {
    return fd_ >= 0;
}

int UniqueFd::release() noexcept {
    return std::exchange(fd_, -1);
}

// Releases ownership before close because retrying close after EINTR is unsafe
// on Linux: the descriptor number may already have been reused.
int UniqueFd::close() noexcept {
    const int old_fd = release();
    return old_fd < 0 ? 0 : ::close(old_fd);
}

void UniqueFd::reset(int replacement) noexcept {
    if (fd_ == replacement) {
        return;
    }
    const int old_fd = std::exchange(fd_, replacement);
    if (old_fd >= 0) {
        ::close(old_fd);
    }
}
