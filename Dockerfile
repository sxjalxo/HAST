# syntax=docker/dockerfile:1

# Tailwind needs Node. Take it from the official image instead of apt-installing hundreds of Debian packages.
FROM node:22-slim AS node
WORKDIR /w
COPY crates/hast-web/package.json crates/hast-web/package-lock.json ./
RUN npm ci

FROM rust:1 AS build
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# flaky or slow networks: retry downloads (rustup resumes the partial file within a RUN) and don't let cargo give up on slow transfers
ENV CARGO_NET_RETRY=10 CARGO_HTTP_TIMEOUT=300 CARGO_HTTP_LOW_SPEED_LIMIT=1
RUN for i in 1 2 3 4 5 6; do rustup target add wasm32-unknown-unknown && exit 0; echo "retry $i"; sleep 5; done; exit 1
# prebuilt trunk (compiling it needs ~400 crates); keep the version in step with CI
RUN curl -fsSL --retry 6 --retry-all-errors --retry-delay 5 https://github.com/trunk-rs/trunk/releases/download/v0.22.1/trunk-x86_64-unknown-linux-gnu.tar.gz | tar -xz -C /usr/local/bin trunk
# trunk would download wasm-bindgen mid-build; preinstall it (must match wasm-bindgen in Cargo.lock)
RUN curl -fsSL --retry 6 --retry-all-errors --retry-delay 5 https://github.com/rustwasm/wasm-bindgen/releases/download/0.2.129/wasm-bindgen-0.2.129-x86_64-unknown-linux-musl.tar.gz \
    | tar -xz --strip-components=1 -C /usr/local/bin wasm-bindgen-0.2.129-x86_64-unknown-linux-musl/wasm-bindgen
WORKDIR /src
COPY . .
COPY --from=node /w/node_modules crates/hast-web/node_modules
RUN cd crates/hast-web && trunk build --release
RUN cargo build --release --locked -p hast-server

FROM debian:stable-slim
COPY --from=build /src/target/release/hast-server /usr/local/bin/hast-server
COPY --from=build /src/crates/hast-web/dist /srv/hast
# one origin serves the UI, the account API and both sockets; put a TLS proxy in front and set HAST_COOKIE_SECURE=1
ENV HAST_STATIC_DIR=/srv/hast HAST_DB=/data/hast.db HAST_HISTORY_FILE=/data/chat.jsonl HAST_MESSAGING_STORE=/data/messaging.json PORT=8000
WORKDIR /data
VOLUME /data
EXPOSE 8000
CMD ["hast-server"]
