FROM haproxy:3.4.2-alpine3.24@sha256:0878b11eb64c433be1b0f578a584b8aca12f6caaa64c8f239b8b556c0dd5eeeb

ARG GUARDIAN_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG GUARDIAN_RELEASE_VERSION=0.0.0-development
ARG GUARDIAN_BUILD_TIME=1970-01-01T00:00:00Z
ARG GUARDIAN_SOURCE_URL=https://github.com/liumingxu0122-hue/vps-guardian
ARG GUARDIAN_LICENSE=Apache-2.0
LABEL org.vps-guardian.runtime.uid=99 \
      org.vps-guardian.runtime.gid=99 \
      org.opencontainers.image.version=$GUARDIAN_RELEASE_VERSION \
      org.opencontainers.image.revision=$GUARDIAN_SOURCE_COMMIT \
      org.opencontainers.image.created=$GUARDIAN_BUILD_TIME \
      org.opencontainers.image.source=$GUARDIAN_SOURCE_URL \
      org.opencontainers.image.licenses=$GUARDIAN_LICENSE
RUN test "$(id -u haproxy):$(id -g haproxy)" = '99:99'
USER 99:99
