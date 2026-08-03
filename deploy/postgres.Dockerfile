FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS gosu-build

ARG GOSU_COMMIT=6456aaa0f3c854d199d0f037f068eb97515b7513
ARG GOSU_SOURCE_SHA256=33d7537d588ea49458b9509bcf4554bdf5ceacc66da71e5caa1058ea3b689c3b
RUN apk add --no-cache ca-certificates wget tar \
    && wget -q "https://codeload.github.com/tianon/gosu/tar.gz/$GOSU_COMMIT" -O /tmp/gosu.tar.gz \
    && echo "$GOSU_SOURCE_SHA256  /tmp/gosu.tar.gz" | sha256sum -c - \
    && mkdir /src \
    && tar -xzf /tmp/gosu.tar.gz -C /src --strip-components=1 \
    && rm -f /tmp/gosu.tar.gz
WORKDIR /src
RUN test "$(cat version.go | sed -n 's/const Version = "\([^"]*\)"/\1/p')" = '1.19' \
    && go mod download \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/gosu . \
    && /out/gosu --version | grep -Eq '^1\.19 \(go1\.26\.5 on linux/'

FROM postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193
RUN test "$(id -u postgres):$(id -g postgres)" = '70:70'
ARG GUARDIAN_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG GUARDIAN_RELEASE_VERSION=0.0.0-development
ARG GUARDIAN_BUILD_TIME=1970-01-01T00:00:00Z
ARG GUARDIAN_SOURCE_URL=https://github.com/liumingxu0122-hue/vps-guardian
ARG GUARDIAN_LICENSE=Apache-2.0
LABEL org.vps-guardian.source-commit=$GUARDIAN_SOURCE_COMMIT \
      org.vps-guardian.runtime.uid=70 \
      org.vps-guardian.runtime.gid=70 \
      org.opencontainers.image.version=$GUARDIAN_RELEASE_VERSION \
      org.opencontainers.image.revision=$GUARDIAN_SOURCE_COMMIT \
      org.opencontainers.image.created=$GUARDIAN_BUILD_TIME \
      org.opencontainers.image.source=$GUARDIAN_SOURCE_URL \
      org.opencontainers.image.licenses=$GUARDIAN_LICENSE
COPY --from=gosu-build /out/gosu /usr/local/bin/gosu
RUN chmod 0755 /usr/local/bin/gosu \
    && gosu --version | grep -Eq '^1\.19 \(go1\.26\.5 on linux/'
USER 70:70
