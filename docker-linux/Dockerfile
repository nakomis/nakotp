FROM rust:1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY pi-rust/ .
RUN cargo build --release

# ── Runtime ──────────────────────────────────────────────────────────────────

FROM alpine:3

RUN apk add --no-cache ca-certificates && \
    mkdir -p /var/log/nakotp /etc/nakotp

COPY --from=builder /build/target/release/nakotp /usr/local/bin/nakotp

EXPOSE 8766
CMD ["/usr/local/bin/nakotp"]
