# Builds for the host architecture (no emulation on Apple Silicon).
FROM rust:1-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang libclang-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo build --release --bin l2-sequencer \
    && cp target/release/l2-sequencer /usr/local/bin/l2-sequencer

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/data
COPY --from=builder /usr/local/bin/l2-sequencer /usr/local/bin/l2-sequencer
COPY resources /resources
WORKDIR /
CMD ["l2-sequencer"]
