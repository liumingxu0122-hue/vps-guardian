FROM golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS restic-build

ARG RESTIC_COMMIT=6aa3a516ce654808a1f28f9fa21e9b7c8e6e90bf
ARG RESTIC_SOURCE_SHA256=6318c51f187bafbaf33d1ab6dcb5abde9a94de11476651cbb2982f1ba89ca8a8
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
    && go run build.go -o /out/restic \
    && /out/restic version | grep -Eq '^restic 0\.19\.1 compiled with go1\.26\.5 '

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY requirements-build.lock ./
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.lock
COPY pyproject.toml README.md LICENSE ./
COPY controller ./controller
RUN python -m build --wheel --no-isolation

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS database-client-build

ARG DEBIAN_SNAPSHOT=20260720T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT trixie-security main" \
      > /etc/apt/sources.list.d/vps-guardian-snapshot.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --no-install-recommends -y mariadb-client postgresql-client-17 \
    && install -D -m 0555 /usr/bin/mariadb-dump /out/mysqldump \
    && install -m 0555 /usr/lib/postgresql/17/bin/pg_dump /out/pg_dump \
    && install -m 0555 /usr/lib/postgresql/17/bin/pg_restore /out/pg_restore \
    && install -m 0555 /usr/lib/postgresql/17/bin/psql /out/psql \
    && /out/mysqldump --version | grep -Eq '11\.8\.6-MariaDB' \
    && /out/pg_dump --version | grep -Eq '^pg_dump \(PostgreSQL\) 17\.' \
    && /out/pg_restore --version | grep -Eq '^pg_restore \(PostgreSQL\) 17\.' \
    && /out/psql --version | grep -Eq '^psql \(PostgreSQL\) 17\.'

FROM python:3.13.14-slim-trixie@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS runtime

ARG GUARDIAN_SOURCE_COMMIT=0000000000000000000000000000000000000000
ARG DEBIAN_SNAPSHOT=20260720T000000Z

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/guardian/bin:$PATH

RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT trixie-security main" \
      > /etc/apt/sources.list.d/vps-guardian-snapshot.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --no-install-recommends -y \
      ca-certificates \
      libpq5 \
      mariadb-client-core \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/apt/sources.list.d/vps-guardian-snapshot.list \
    && groupadd --gid 10001 guardian \
    && useradd --uid 10001 --gid guardian --home-dir /var/lib/vps-guardian --shell /usr/sbin/nologin guardian \
    && groupadd --gid 10002 guardian-backup \
    && useradd --uid 10002 --gid guardian-backup \
      --home-dir /var/lib/vps-guardian-backup --shell /usr/sbin/nologin guardian-backup

COPY --from=database-client-build /out/mysqldump /out/pg_dump /out/pg_restore /out/psql /usr/local/bin/
RUN pg_dump --version | grep -Eq '^pg_dump \(PostgreSQL\) 17\.' \
    && pg_restore --version | grep -Eq '^pg_restore \(PostgreSQL\) 17\.' \
    && psql --version | grep -Eq '^psql \(PostgreSQL\) 17\.' \
    && mysql --version | grep -Eq '11\.8\.6-MariaDB' \
    && mysqldump --version | grep -Eq '11\.8\.6-MariaDB'
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

COPY --chmod=0555 deploy/controller-entrypoint.sh /usr/local/bin/controller-entrypoint
USER guardian:guardian
EXPOSE 8090
ENTRYPOINT ["controller-entrypoint"]
CMD ["uvicorn", "guardian.main:app", "--host", "0.0.0.0", "--port", "8090", "--no-server-header"]
