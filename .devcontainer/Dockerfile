FROM docker.io/rust:1.89-slim

# add rp235x targets and rust IDE tools
RUN rustup target add thumbv8m.main-none-eabihf \
    && rustup target add riscv32imac-unknown-none-elf \
    && rustup component add clippy rustfmt

RUN cargo install cargo-binstall \
    && cargo binstall probe-rs-tools

# add ts-tvl for tests
ARG TVL_VERSION="2.2"
RUN apt-get update \
    && apt-get install -y python3-pip wget sccache \
    && wget -O /tmp/tvl-2.2-py3-none-any.whl https://github.com/tropicsquare/ts-tvl/releases/download/${TVL_VERSION}/tvl-${TVL_VERSION}-py3-none-any.whl \
    && pip install --prefix=/usr /tmp/tvl-${TVL_VERSION}-py3-none-any.whl