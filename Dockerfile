FROM ubuntu:22.04
WORKDIR /usr/src/app

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y \
    git curl cmake ninja-build python3 build-essential \
    libssl-dev libsqlite3-dev pkg-config gcc g++

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.81
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version
RUN rustup target add aarch64-unknown-linux-gnu

# Clone the RISC Zero repository
RUN git clone --branch fix/v1.2.2-syntax-unsupported-architecture https://github.com/jonas089/risc0.git /usr/src/risc0
WORKDIR /usr/src/risc0

RUN cargo install --path rzup
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rzup --help
RUN rzup install

WORKDIR /usr/src/app
COPY . .
RUN cargo build --release -F local-net
RUN mkdir -p /var/data/ && chmod -R 777 /var/data/
CMD ["./target/release/l2-sequencer"]
