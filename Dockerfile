# Use amd64 Ubuntu base
FROM --platform=linux/amd64 ubuntu:22.04

# Set working directory
WORKDIR /usr/src/app

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    curl build-essential \
    libssl-dev pkg-config gcc g++ libsqlite3-dev

# Install Rust explicitly for x86_64
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.81 --default-host x86_64-unknown-linux-gnu

# Ensure Rust binaries are available in PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Manually source Rust environment and verify installation
RUN /bin/bash -c "source $HOME/.cargo/env && rustup show && rustc --version"

WORKDIR /usr/src/app
COPY . .

# Build the Rust project for x86_64
RUN /bin/bash -c "source $HOME/.cargo/env && cargo build --release --target x86_64-unknown-linux-gnu"

# Ensure correct permissions
RUN mkdir -p /var/data/ && chmod -R 777 /var/data/

# Run the built Rust application
CMD ["./target/x86_64-unknown-linux-gnu/release/l2-sequencer"]
