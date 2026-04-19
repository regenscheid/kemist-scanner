# Multi-stage Docker build for kemist.
#
# Build stage uses the official rust:slim image to compile a release
# binary with full feature set (incl. http-checks + legacy native-tls).
# Runtime stage uses distroless/cc so the final image has no shell,
# no package manager, just the binary + dynamic libs it needs.
#
# Target compressed size: < 50 MB.

FROM rust:1.86-slim-bookworm AS builder

# Dependencies required to build aws-lc-rs and native-tls.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        cmake \
        clang \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Prime the dependency cache — copy Cargo manifests, build a dummy
# binary so later code changes reuse the ~500MB of cached compiled deps.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

# Real build.
COPY build.rs ./
COPY src ./src
COPY schemas ./schemas
# Force cargo to notice the real main.rs and re-link (touches stale
# fingerprint from the dummy build).
RUN touch src/main.rs && cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────
# distroless/cc-debian12 ships glibc and the minimum cc runtime.
# No shell, no coreutils, no package manager. Drop cap-add=NET_ADMIN
# isn't needed — kemist only opens outbound TCP connections.
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/kemist /usr/local/bin/kemist

# Run as the non-root user baked into the distroless image.
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/kemist"]
CMD ["--help"]

# Image metadata (OCI standard labels).
LABEL org.opencontainers.image.title="kemist" \
      org.opencontainers.image.description="TLS + PQC observation scanner" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.source="https://github.com/regenscheid/kemist-scanner" \
      org.opencontainers.image.documentation="https://github.com/regenscheid/kemist-scanner/blob/main/README.md"
