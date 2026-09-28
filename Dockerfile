FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    zip \
    unzip \
    tar \
    pkg-config \
    ninja-build \
    autoconf \
    autoconf-archive \
    automake \
    libtool \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Install vcpkg
ENV VCPKG_ROOT=/opt/vcpkg
RUN git clone --depth 1 https://github.com/microsoft/vcpkg.git ${VCPKG_ROOT} && \
    ${VCPKG_ROOT}/bootstrap-vcpkg.sh -disableMetrics

# Copy dependency manifest first to cache vcpkg build
WORKDIR /app
COPY vcpkg.json ./
RUN ${VCPKG_ROOT}/vcpkg install --triplet x64-linux

# Copy project files
COPY CMakeLists.txt ./
COPY src/ ./src/
COPY tests/ ./tests/
COPY config/ ./config/

# Install dependencies and build
RUN cmake -B build \
    -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=OFF \
    -G Ninja && \
    cmake --build build --target p2p_node

# ─── Runtime image ───────────────────────────────────────────────
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and config
COPY --from=builder /app/build/p2p_node /usr/local/bin/p2p_node
COPY config/default.toml /etc/p2p/default.toml

# Create directories
RUN mkdir -p /data /results /downloads

# Default config path
ENV P2P_CONFIG=/etc/p2p/default.toml

EXPOSE 9000

ENTRYPOINT ["p2p_node"]
CMD ["--config", "/etc/p2p/default.toml", "--data-dir", "/data"]
