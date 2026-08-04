FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS restic-build

ARG RESTIC_COMMIT=6aa3a516ce654808a1f28f9fa21e9b7c8e6e90bf
ARG RESTIC_SOURCE_SHA256=6318c51f187bafbaf33d1ab6dcb5abde9a94de11476651cbb2982f1ba89ca8a8
ARG RESTIC_X_TEXT_VERSION=v0.40.0
ARG RESTIC_X_TEXT_MODULE_SUM=h1:Ub2Z6/xjgF1WrYQz2nuITOEegKFtiIy+rieRJ5lHZKs=
ARG GRPC_GO_VERSION=v1.82.1
ARG GRPC_GO_MODULE_SUM=h1:NnAxzGRA0677vCa4BUkOAnO5+FfQqVl9iUXeD0IqcGE=
ARG CPYTHON_HTML_PARSER_COMMIT=7933f4bf7131aa4140750f9404f5de0aa2969ced
ARG CPYTHON_HTML_PARSER_SHA256=4274e9112adf3fa57c7f9afa7c9b5c631456b18b7403cc627cc5027d02cdd2ae
RUN apk add --no-cache ca-certificates wget tar \
    && mkdir -p /out \
    && wget -q "https://codeload.github.com/restic/restic/tar.gz/$RESTIC_COMMIT" -O /tmp/restic.tar.gz \
    && echo "$RESTIC_SOURCE_SHA256  /tmp/restic.tar.gz" | sha256sum -c - \
    && wget -q \
      "https://raw.githubusercontent.com/python/cpython/$CPYTHON_HTML_PARSER_COMMIT/Lib/html/parser.py" \
      -O /out/html-parser.py \
    && echo "$CPYTHON_HTML_PARSER_SHA256  /out/html-parser.py" | sha256sum -c - \
    && mkdir /src \
    && tar -xzf /tmp/restic.tar.gz -C /src --strip-components=1 \
    && rm -f /tmp/restic.tar.gz
WORKDIR /src
RUN test "$(cat VERSION)" = '0.19.1' \
    && go mod edit -require="golang.org/x/text@$RESTIC_X_TEXT_VERSION" \
    && go mod download "golang.org/x/text@$RESTIC_X_TEXT_VERSION" \
    && grep -Fx "golang.org/x/text $RESTIC_X_TEXT_VERSION $RESTIC_X_TEXT_MODULE_SUM" go.sum \
    && go mod edit -require="google.golang.org/grpc@$GRPC_GO_VERSION" \
    && go mod download "google.golang.org/grpc@$GRPC_GO_VERSION" \
    && grep -Fx "google.golang.org/grpc $GRPC_GO_VERSION $GRPC_GO_MODULE_SUM" go.sum \
    && go mod tidy \
    && grep -Fx "golang.org/x/text $RESTIC_X_TEXT_VERSION $RESTIC_X_TEXT_MODULE_SUM" go.sum \
    && grep -Fx "google.golang.org/grpc $GRPC_GO_VERSION $GRPC_GO_MODULE_SUM" go.sum \
    && go mod verify \
    && test "$(go list -m -f '{{.Version}}' golang.org/x/text)" = "$RESTIC_X_TEXT_VERSION" \
    && test "$(go list -m -f '{{.Version}}' google.golang.org/grpc)" = "$GRPC_GO_VERSION" \
    && go run build.go -o /out/restic \
    && go version -m /out/restic \
      | grep -F "golang.org/x/text	$RESTIC_X_TEXT_VERSION	$RESTIC_X_TEXT_MODULE_SUM" \
    && go version -m /out/restic \
      | grep -F "google.golang.org/grpc	$GRPC_GO_VERSION	$GRPC_GO_MODULE_SUM" \
    && /out/restic version | grep -Eq '^restic 0\.19\.1 compiled with go1\.26\.5 '

FROM python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY requirements-build.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.lock
COPY pyproject.toml README.md LICENSE ./
COPY controller ./controller
RUN python -m build --wheel --no-isolation

FROM python:3.13.14-alpine3.24@sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0 AS runtime

ARG GUARDIAN_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG GUARDIAN_RELEASE_VERSION=0.0.0-development
ARG GUARDIAN_BUILD_TIME=1970-01-01T00:00:00Z
ARG GUARDIAN_SOURCE_URL=https://github.com/liumingxu0122-hue/vps-guardian
ARG GUARDIAN_LICENSE=Apache-2.0
LABEL org.opencontainers.image.version=$GUARDIAN_RELEASE_VERSION \
      org.vps-guardian.runtime.uid=10001 \
      org.vps-guardian.runtime.gid=10001 \
      org.vps-guardian.runtime.backup.uid=10002 \
      org.vps-guardian.runtime.backup.gid=10002 \
      org.opencontainers.image.revision=$GUARDIAN_SOURCE_COMMIT \
      org.opencontainers.image.created=$GUARDIAN_BUILD_TIME \
      org.opencontainers.image.source=$GUARDIAN_SOURCE_URL \
      org.opencontainers.image.licenses=$GUARDIAN_LICENSE

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/guardian/bin:$PATH

RUN apk add --no-cache \
      ca-certificates \
      mariadb-client=11.8.8-r0 \
      postgresql17-client=17.10-r0 \
    && addgroup -g 10001 -S guardian \
    && adduser -u 10001 -S -D -H -h /var/lib/vps-guardian \
      -s /sbin/nologin -G guardian guardian \
    && addgroup -g 10002 -S guardian-backup \
    && adduser -u 10002 -S -D -H -h /var/lib/vps-guardian-backup \
      -s /sbin/nologin -G guardian-backup guardian-backup \
    && pg_dump --version | grep -Eq '^pg_dump \(PostgreSQL\) 17\.' \
    && pg_restore --version | grep -Eq '^pg_restore \(PostgreSQL\) 17\.' \
    && psql --version | grep -Eq '^psql \(PostgreSQL\) 17\.' \
    && mysql --version | grep -Eq '11\.8\.8-MariaDB' \
    && mysqldump --version | grep -Eq '11\.8\.8-MariaDB'
COPY --from=restic-build /out/restic /usr/local/bin/restic
COPY --from=restic-build /out/html-parser.py /usr/local/lib/python3.13/html/parser.py
RUN echo '4274e9112adf3fa57c7f9afa7c9b5c631456b18b7403cc627cc5027d02cdd2ae  /usr/local/lib/python3.13/html/parser.py' \
      | sha256sum -c - \
    && python --version | grep -Eq '^Python 3\.13\.' \
    && python -c 'import html.parser; parser = html.parser.HTMLParser(); assert hasattr(parser, "_pending")' \
    && restic version | grep -Eq '^restic 0\.19\.1 compiled with go1\.26\.5 '

WORKDIR /opt/guardian
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock
COPY --from=build /src/dist/vps_guardian-*.whl /tmp/
RUN python -m pip install --no-cache-dir --no-deps /tmp/vps_guardian-*.whl \
    && rm -f /tmp/vps_guardian-*.whl
COPY --from=build /src/controller/alembic.ini ./controller/alembic.ini
COPY --from=build /src/controller/migrations ./controller/migrations
COPY runbooks ./runbooks
RUN chmod -R a=rX /opt/guardian/controller /opt/guardian/runbooks
RUN printf '%s\n' "$GUARDIAN_SOURCE_COMMIT" | grep -Eq '^[A-Fa-f0-9]{40}$' \
    && printf '%s\n' "$GUARDIAN_SOURCE_COMMIT" > /opt/guardian/SOURCE_COMMIT \
    && chown root:root /opt/guardian/SOURCE_COMMIT \
    && chmod 0444 /opt/guardian/SOURCE_COMMIT
RUN install -d -o guardian -g guardian -m 0750 /var/lib/vps-guardian /var/lib/vps-guardian/data \
    && install -d -o guardian-backup -g guardian-backup -m 0750 \
      /var/lib/vps-guardian-backup /var/lib/vps-guardian-backup/staging \
      /var/lib/vps-guardian-backup/restic /var/cache/vps-guardian-backup
RUN test "$(id -u guardian):$(id -g guardian)" = '10001:10001' \
    && test "$(id -u guardian-backup):$(id -g guardian-backup)" = '10002:10002'

COPY --chmod=0555 deploy/controller-entrypoint.sh /usr/local/bin/controller-entrypoint
USER 10001:10001
EXPOSE 8090
ENTRYPOINT ["controller-entrypoint"]
CMD ["uvicorn", "guardian.main:app", "--host", "0.0.0.0", "--port", "8090", "--no-server-header"]
