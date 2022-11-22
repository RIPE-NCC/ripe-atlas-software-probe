FROM centos:7

MAINTAINER phomburg@ripe.net

RUN yum -y update

# config_opts['chroot_setup_cmd'] from https://github.com/rpm-software-management/mock/blob/main/mock-core-configs/etc/mock/templates/centos-7.tpl#L3
RUN yum -y install bash bzip2 coreutils cpio diffutils findutils gawk gcc gcc-c++ grep gzip info make patch redhat-rpm-config rpm-build sed shadow-utils tar unzip util-linux which xz
RUN yum -y install autoconf automake yum-utils createrepo_c git-core libtool openssl-devel
