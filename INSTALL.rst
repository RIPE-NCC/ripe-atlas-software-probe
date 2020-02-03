Installation Instructions
=========================

##### To create a RPM for CentOS 7 or CentOS 8

- ```yum update && yum install git tar rpm-build openssl-devel autoconf automake libtool make```
- ```git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git```
- ```ripe-atlas-software-probe/build-config/centos/bin/make-tars```
  (this will create a directory called rpmbuild)
- ```rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec```
- This will leave the RPM in rpmbuild/RPMS/x86_64

##### To create a deb for Debian or Debian-based distros

Currently only the Debian Build system includes support for amd64, arm64, and armhf.

- ```apt update && apt install git tar fakeroot libssl-dev libcap2-bin autoconf automake libtool build-essential```
- ```git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git```
- ```./ripe-atlas-software-probe/build-config/debian/bin/make-deb```
- This will leave the .deb in the current working directory.
- ```dpkg -i atlasswprobe-??????.deb```

