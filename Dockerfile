# syntax=docker/dockerfile:1

FROM rust:1.98-bookworm AS build
ENV CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
RUN apt-get update \
 && apt-get install --yes --no-install-recommends protobuf-compiler \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/Cargo.toml
COPY crates/eval/Cargo.toml crates/eval/Cargo.toml
COPY crates/proto/Cargo.toml crates/proto/Cargo.toml
COPY crates/server/Cargo.toml crates/server/Cargo.toml
RUN mkdir -p crates/core/src crates/core/benches crates/eval/src crates/proto/src crates/server/src \
 && touch crates/core/src/lib.rs crates/core/benches/stages.rs crates/core/benches/gate.rs \
 && touch crates/eval/src/main.rs crates/proto/src/lib.rs \
 && printf 'fn main() {}\n' > crates/proto/build.rs \
 && printf 'fn main() {}\n' > crates/server/src/main.rs \
 && cargo build --release --locked -p quantification-server --features ccr
COPY . .
# COPY preserves source mtimes, which can predate the stub build above; without
# this, cargo considers the stubbed crates fresh and ships the stub binary.
RUN find crates -name '*.rs' -exec touch {} + \
 && touch crates/proto/compressor/v1/compressor.proto \
 && cargo build --release --locked -p quantification-server --features ccr

FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=build /src/target/release/quantification-server /usr/local/bin/quantification-server
USER nonroot:nonroot
ENV QUANT_HTTP_ADDR=0.0.0.0:8080 \
    QUANT_GRPC_ADDR=0.0.0.0:50051
EXPOSE 8080 50051
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/quantification-server"]
