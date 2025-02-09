FROM --platform=linux/amd64 ubuntu:22.04

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y --fix-missing
RUN apt-get clean && apt-get autoremove -y

RUN apt-get update && apt-get install -y \
    git curl cmake ninja-build python3 build-essential \
    libssl-dev pkg-config gcc g++ libsqlite3-dev

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.81
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustc --version

# Clone the RISC Zero repository
RUN git clone https://github.com/risc0/risc0.git /usr/src/risc0
WORKDIR /usr/src/risc0

# Install rzup manually using Cargo
RUN cargo install --path rzup
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rzup --help

ARG RISCVM_VERSION="v1.2.2"
RUN git fetch --tags && git checkout tags/${RISCVM_VERSION}
RUN cargo install --path risc0/cargo-risczero
RUN rzup install


WORKDIR /usr/src/app
COPY . .
RUN cargo build --release -F local-net
RUN mkdir -p /var/data/ && chmod -R 777 /var/data/
CMD ["./target/release/l2-sequencer"]
