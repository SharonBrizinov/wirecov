FROM ubuntu:22.04

ARG WIRESHARK_VERSION=master
ARG BUILD_JOBS=0

ENV DEBIAN_FRONTEND=noninteractive

LABEL wirecov.tool="wirecov"
LABEL wirecov.wireshark_version="${WIRESHARK_VERSION}"

# Install build dependencies + optional libs for maximum dissector coverage
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates cmake make g++ gcc flex bison python3 perl pkg-config \
    libglib2.0-dev libpcap-dev libgcrypt20-dev libc-ares-dev \
    libpcre2-dev libspeexdsp-dev libxml2-dev \
    libgnutls28-dev liblua5.4-dev libnghttp2-dev libnghttp3-dev \
    libkrb5-dev liblz4-dev libsnappy-dev libzstd-dev \
    libsmi2-dev libmaxminddb-dev libssh-dev libbrotli-dev \
    libminizip-dev libxxhash-dev libopus-dev libsbc-dev \
    libnl-3-dev libnl-cli-3-dev libnl-route-3-dev \
    libsystemd-dev libcap-dev \
    lcov \
    && rm -rf /var/lib/apt/lists/*

# Clone Wireshark at specified version (shallow for build speed)
# Supports tags (v4.6.4), branches (master), and commit hashes.
# Try --branch first (works for tags/branches), fall back to full clone + checkout (for commits).
RUN git clone --depth 1 --branch ${WIRESHARK_VERSION} \
    https://gitlab.com/wireshark/wireshark.git /src/wireshark 2>/dev/null || \
    (git clone https://gitlab.com/wireshark/wireshark.git /src/wireshark && \
     cd /src/wireshark && git checkout ${WIRESHARK_VERSION})

WORKDIR /src/wireshark/build

# Configure with gcov coverage instrumentation
RUN cmake .. \
    -DCMAKE_C_FLAGS="--coverage -g -O0" \
    -DCMAKE_CXX_FLAGS="--coverage -g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="--coverage" \
    -DCMAKE_SHARED_LINKER_FLAGS="--coverage" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_wireshark=OFF \
    -DBUILD_tshark=ON \
    -DBUILD_rawshark=OFF \
    -DBUILD_dumpcap=ON \
    -DBUILD_editcap=OFF \
    -DBUILD_capinfos=OFF \
    -DBUILD_mergecap=OFF \
    -DBUILD_reordercap=OFF \
    -DBUILD_text2pcap=OFF \
    -DBUILD_sharkd=OFF \
    -DENABLE_PLUGINS=ON

# Build (the slow step)
RUN if [ "$BUILD_JOBS" = "0" ]; then \
      make -j$(nproc); \
    else \
      make -j${BUILD_JOBS}; \
    fi

# Capture baseline coverage (zero counters) — baked into image for reuse
RUN lcov --capture --initial \
    --directory /src/wireshark/build \
    --base-directory /src/wireshark \
    --no-external \
    --output-file /src/baseline.info \
    --quiet 2>/dev/null || true

# Fetch full git history and extract dissector dates (first created / last updated)
# This runs after the build so it doesn't slow the critical path.
COPY docker/extract_dates.py /src/extract_dates.py
RUN cd /src/wireshark && \
    git fetch --unshallow 2>/dev/null || true && \
    python3 /src/extract_dates.py 2>&1 || echo '{}' > /src/dissector_dates.json

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
