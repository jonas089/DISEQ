FROM --platform=linux/arm64 ubuntu:22.04
WORKDIR /usr/src/app
# Install dependencies
RUN apt-get update && apt-get install -y \
    curl cmake ninja-build python3 build-essential libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.84
ENV PATH="/root/.cargo/bin:${PATH}"
# Verify Rust installation
RUN rustc --version
# Install necessary dependencies
RUN apt-get update && apt-get install git curl cmake ninja-build python3 build-essential libssl-dev pkg-config -y
# Install cargo-binstall
RUN cargo install cargo-binstall
# Install cargo-risczero using binstall
RUN cargo binstall cargo-risczero --version 1.2.0 -y
# Build the risc0 toolchain
RUN cargo risczero build-toolchain
# Copy the entire Rust project into the container
COPY . .
# Build the Rust project with the necessary feature
RUN export RUSTFLAGS="-Z unstable-options"
RUN cargo build --release -F local-net
RUN mkdir -p /var/data/
RUN chmod -R 777 /var/data/

# Set the entrypoint to run the compiled binary
CMD ["./target/release/l2-sequencer"]