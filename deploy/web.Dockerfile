FROM node:24-trixie-slim@sha256:ae91dcc111a68c9d2d81ff2a17bda61be126426176fde6fe7d08ab13b7f50573 AS build
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS caddy-build

ARG CADDY_VERSION=v2.11.4
ARG CADDY_COMMIT=e2eee6a7fce366321294c9c2a79f3146891dcbdf
ARG CADDY_SOURCE_SHA256=a593bd7077c76102ca76d19287a5e247d4e359dd67eddbc933f865afd3c131eb
RUN apk add --no-cache ca-certificates wget tar \
    && wget -q "https://codeload.github.com/caddyserver/caddy/tar.gz/$CADDY_COMMIT" -O /tmp/caddy.tar.gz \
    && echo "$CADDY_SOURCE_SHA256  /tmp/caddy.tar.gz" | sha256sum -c - \
    && mkdir /src \
    && tar -xzf /tmp/caddy.tar.gz -C /src --strip-components=1 \
    && rm -f /tmp/caddy.tar.gz
WORKDIR /src
RUN go mod download
RUN test "$(grep '^module ' go.mod | awk '{print $2}')" = 'github.com/caddyserver/caddy/v2' \
    && test "$CADDY_VERSION" = 'v2.11.4' \
    && go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X github.com/caddyserver/caddy/v2.CustomVersion=$CADDY_VERSION" \
      -o /out/caddy ./cmd/caddy
RUN /out/caddy version | grep -Eq '^v2\.11\.4( |$)'

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 AS runtime
USER root
COPY --from=caddy-build /out/caddy /usr/bin/caddy
RUN apk upgrade --no-cache \
    && apk del --no-cache curl libcurl c-ares \
    && ! apk info --exists curl libcurl c-ares \
    && caddy version | grep -Eq '^v2\.11\.4( |$)'
COPY --from=build /app/dist /srv
COPY deploy/Caddyfile /etc/caddy/Caddyfile
USER 1000:1000
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
