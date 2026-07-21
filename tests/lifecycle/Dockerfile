FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG DEBIAN_SNAPSHOT=20260720T000000Z

RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT trixie-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT trixie-security main" \
      > /etc/apt/sources.list.d/vps-guardian-snapshot.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install --no-install-recommends -y \
      coreutils \
      curl \
      findutils \
      git \
      grep \
      passwd \
      sed \
      tar \
      util-linux \
    && rm -f /etc/apt/sources.list.d/vps-guardian-snapshot.list \
    && rm -rf /var/lib/apt/lists/*
