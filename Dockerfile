# Use amd64 Ubuntu base
FROM --platform=linux/amd64 ubuntu:22.04

# Set working directory
WORKDIR /usr/src/app

# Update and install dependencies
RUN apt-get update && apt-get install -y \
    git curl cmake ninja-build python3 build-essential \
    libssl-dev pkg-config gcc g++ libsqlite3-dev

# Install Rust explicitly for x86_64
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.81 --default-host x86_64-unknown-linux-gnu

# Ensure Rust binaries are available in PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Manually source Rust environment and verify installation
RUN /bin/bash -c "source $HOME/.cargo/env && rustup show && rustc --version"

# Clone the RISC Zero repository
RUN git clone https://github.com/risc0/risc0.git /usr/src/risc0
WORKDIR /usr/src/risc0

# Install rzup manually using Cargo
RUN /bin/bash -c "source $HOME/.cargo/env && cargo install --path rzup"
ENV PATH="/root/.cargo/bin:$PATH"
RUN /bin/bash -c "source $HOME/.cargo/env && rzup --help"

ARG RISCVM_VERSION="v1.2.2"
RUN git fetch --tags && git checkout tags/${RISCVM_VERSION}
RUN /bin/bash -c "source $HOME/.cargo/env && cargo install --path risc0/cargo-risczero"
RUN /bin/bash -c "source $HOME/.cargo/env && rzup install cpp"
RUN /bin/bash -c "source $HOME/.cargo/env && rzup install"

# Return to app directory
WORKDIR /usr/src/app
COPY . .

# Build the Rust project for x86_64
RUN /bin/bash -c "source $HOME/.cargo/env && cargo build --release --target x86_64-unknown-linux-gnu -F local-net"

# Ensure correct permissions
RUN mkdir -p /var/data/ && chmod -R 777 /var/data/

# Run the built Rust application
CMD ["./target/x86_64-unknown-linux-gnu/release/l2-sequencer"]
