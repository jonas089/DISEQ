# Use the Rust official image
FROM rust:latest

# Set the working directory
WORKDIR /usr/src/app

# Install necessary dependencies
RUN apt-get update && apt-get install curl cmake ninja-build python3 -y

# Install cargo-binstall
RUN cargo install cargo-binstall

# Install cargo-risczero using binstall
RUN cargo binstall cargo-risczero --version 1.2.0 -y

# Build the risc0 toolchain
RUN cargo risczero build-toolchain --version v2024-04-22.0

# Copy the entire Rust project into the container
COPY . .

# Build the Rust project with the necessary feature
RUN cargo build --release -F local-net

RUN mkdir -p /var/data/

RUN chmod -R 777 /var/data/

# Set the entrypoint to run the compiled binary
CMD ["./target/release/l2-sequencer"]