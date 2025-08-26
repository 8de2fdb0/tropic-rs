FROM docker.io/rust:latest

# add rp235x targets and rust IDE tools
RUN rustup target add thumbv8m.main-none-eabihf \
    && rustup target add riscv32imac-unknown-none-elf \
    && rustup component add clippy rustfmt

RUN cargo install cargo-binstall \
    && cargo binstall probe-rs-tools

# add ts-tvl for tests

RUN apt-get update \
    && apt-get install -y python3-pip \
    && wget -O /tmp/tvl-2.2-py3-none-any.whl https://github.com/tropicsquare/ts-tvl/releases/download/2.2/tvl-2.2-py3-none-any.whl \
    && pip install --prefix=/usr /tmp/tvl-2.2-py3-none-any.whl