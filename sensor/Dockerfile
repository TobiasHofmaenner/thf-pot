# syntax=docker/dockerfile:1.7
# Static musl build into a scratch image: one binary, the persona bundles, no shell, no interpreter.

FROM rust:1-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
# Dependency layer first so source edits do not re-download or recompile crates.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs && cargo build --release --locked 2>/dev/null || true
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

RUN mkdir /data && chown 65534:65534 /data

FROM scratch
COPY --from=build /src/target/release/thf-pot-sensor /thf-pot-sensor
COPY bundles /bundles
COPY profiles.toml /profiles.toml
# /data is pre-created owned by nobody so a fresh named volume inherits writable ownership.
COPY --from=build --chown=65534:65534 /data /data
# Non-root. The node listens on 8080/8443; map 80/443 to them at the host.
USER 65534:65534
VOLUME ["/data"]
EXPOSE 8080 8443
ENV LOG_DIR=/data BUNDLES_DIR=/bundles PROFILES_FILE=/profiles.toml RUST_LOG=info
ENTRYPOINT ["/thf-pot-sensor"]
