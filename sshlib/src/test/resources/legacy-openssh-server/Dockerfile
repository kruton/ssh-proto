FROM debian:bullseye-20250811-slim@sha256:849d9d34d5fe0bf88b5fb3d09eb9684909ac4210488b52f4f7bbe683eedcb851 AS base

# The live Bullseye security repository is retired; freeze its build dependencies.
RUN printf '%s\n' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20250901T000000Z bullseye main' \
    'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20250901T000000Z bullseye-security main' \
    > /etc/apt/sources.list

FROM base AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl zlib1g-dev libcrypt-dev && \
    rm -rf /var/lib/apt/lists/*

# Modern OpenSSL has opaque structs which these unmodified SSH releases predate.
RUN curl -fsSL https://codeload.github.com/openssl/openssl/tar.gz/refs/tags/OpenSSL_1_0_2u -o /tmp/openssl.tar.gz && \
    echo '82fa58e3f273c53128c6fe7e3635ec8cda1319a10ce1ad50a987c3df0deeef05  /tmp/openssl.tar.gz' | sha256sum -c - && \
    tar -xzf /tmp/openssl.tar.gz -C /tmp && \
    cd /tmp/openssl-OpenSSL_1_0_2u && \
    ./config no-shared --prefix=/opt/openssl && make -j2 && make install_sw

ARG OPENSSH_VERSION
ARG OPENSSH_SHA256
RUN curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz" -o /tmp/openssh.tar.gz && \
    echo "${OPENSSH_SHA256}  /tmp/openssh.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/openssh.tar.gz -C /tmp && \
    cd "/tmp/openssh-${OPENSSH_VERSION}" && \
    CFLAGS=-fcommon LDFLAGS=-L/opt/openssl/lib LIBS='-lcrypto -ldl' \
    ./configure --prefix=/opt/ssh --sysconfdir=/etc/ssh \
        --with-ssl-dir=/opt/openssl --without-pam --with-privsep-path=/var/empty && \
    make -j2 && make install

FROM base
RUN apt-get update && apt-get install -y --no-install-recommends zlib1g libcrypt1 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /bin/sh testuser && echo 'testuser:testpass' | chpasswd && \
    useradd -r -d /var/empty -s /usr/sbin/nologin sshd && mkdir -p /var/empty /etc/ssh
COPY --from=build /opt/ssh /opt/ssh
COPY sshd_config /etc/ssh/sshd_config
ARG OPENSSH_VERSION
RUN /opt/ssh/bin/ssh-keygen -t rsa -b 2048 -N '' -f /etc/ssh/ssh_host_rsa_key && \
    if [ "$OPENSSH_VERSION" = 5.3p1 ]; then \
        /opt/ssh/bin/ssh-keygen -t rsa1 -b 2048 -N '' -f /etc/ssh/ssh_host_key && \
        echo 'HostKey /etc/ssh/ssh_host_key' >> /etc/ssh/sshd_config; \
    fi
EXPOSE 22
CMD ["/opt/ssh/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
