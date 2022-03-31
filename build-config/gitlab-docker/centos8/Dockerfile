FROM centos:8.3.2011

MAINTAINER phomburg@ripe.net

RUN cd /etc/yum.repos.d/
RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
RUN sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
RUN yum -y update
RUN yum -y install git
RUN yum -y install rpm-build
RUN yum -y install openssl-devel
RUN yum -y install ncurses-devel
RUN yum -y install autoconf
RUN yum -y install automake
RUN yum -y install libtool
RUN yum -y install make
