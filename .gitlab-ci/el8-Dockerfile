FROM oraclelinux:8

MAINTAINER mmavropoulos@ripe.net

RUN dnf -y update

# Replace coreutils-single by coreutils
RUN dnf -y swap coreutils-single coreutils

RUN dnf -y install tar gcc-c++ redhat-rpm-config redhat-release which xz sed make bzip2 gzip gcc coreutils unzip shadow-utils diffutils cpio bash gawk rpm-build info patch util-linux findutils grep
RUN dnf -y install autoconf automake dnf-utils createrepo_c git-core libtool openssl-devel rpmlint
