FROM debian:11.0

MAINTAINER gmeyer@ripe.net

RUN apt-get update
RUN apt-get dist-upgrade -y
RUN apt-get install -y file libgfshare-bin binutils apt-utils debsigs openssl rpm gpg git createrepo-c
