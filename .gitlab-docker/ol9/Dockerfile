FROM oraclelinux:9

MAINTAINER gmeyer@ripe.net

RUN dnf -y update

# Replace coreutils-single by coreutils
RUN dnf -y swap coreutils-single coreutils

# from https://github.com/rpm-software-management/mock/blob/main/mock-core-configs/etc/mock/templates/centos-7.tpl#L3
RUN dnf -y install bash bzip2 coreutils cpio diffutils redhat-release findutils gawk glibc-minimal-langpack grep gzip info patch redhat-rpm-config rpm-build sed shadow-utils tar unzip util-linux which xz
RUN dnf -y install autoconf automake dnf-utils createrepo_c git-core libtool openssl-devel rpmlint
