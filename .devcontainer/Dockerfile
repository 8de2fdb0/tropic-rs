FROM docker.io/rust:latest

# add rp235x targets and rust IDE tools
RUN rustup target add thumbv8m.main-none-eabihf \
    && rustup target add riscv32imac-unknown-none-elf \
    && rustup component add clippy rustfmt

RUN cargo install cargo-binstall \
    && cargo binstall probe-rs-tools
