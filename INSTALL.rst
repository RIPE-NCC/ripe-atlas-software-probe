Installation Instructions
=========================

##### To create a RPM for CentOS 7 or CentOS 8

- ``yum update && yum install git tar rpm-build openssl-devel autoconf automake libtool make``
- ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- ``ripe-atlas-software-probe/build-config/centos/bin/make-tars``
  (this will create a directory called rpmbuild)
- ``rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec``
- This will leave the RPM in rpmbuild/RPMS/x86_64

##### To create a deb for Debian or Debian-based distros

Currently only the Debian Build system includes support for amd64, arm64, and armhf.

- Get the needed tools: ``sudo apt update && sudo apt install git tar fakeroot libssl-dev libcap2-bin autoconf automake libtool build-essential``
- Clone the repo: ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- Build the needed .deb file in the current working directory: ``./ripe-atlas-software-probe/build-config/debian/bin/make-deb``
- Install this .deb file: ``sudo dpkg -i atlasswprobe-??????.deb``
- The public key is stored in ``/var/atlas-probe/etc/probe_key.pub``
