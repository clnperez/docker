# Copied from the amd64 version since I'm not planning to update the ppc64le one any time soon to include opensuse

FROM clnperez/builder:13.2

RUN zypper --non-interactive install ca-certificates* curl gzip rpm-build
RUN zypper --non-interactive install libbtrfs-devel device-mapper-devel glibc-static  libselinux-devel libtool-ltdl-devel pkg-config selinux-policy selinux-policy-devel systemd-devel tar git cmake vim systemd-rpm-macros

ENV GO_VERSION 1.7.5
RUN curl -fSL "https://golang.org/dl/go${GO_VERSION}.linux-ppc64le.tar.gz" | tar xzC /usr/local
ENV PATH $PATH:/usr/local/go/bin

ENV AUTO_GOPATH 1

ENV DOCKER_BUILDTAGS pkcs11 selinux
ENV RUNC_BUILDTAGS selinux

