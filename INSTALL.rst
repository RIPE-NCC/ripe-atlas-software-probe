Installation Instructions
=========================

To create a RPM for CentOS 7 or CentOS 8:

- yum install git tar rpm-build openssl-devel autoconf automake libtool make
- git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
- Run ripe-atlas-software-probe/build-config/centos/bin/make-tars
  (this will create a directory called rpmbuild)
- Run rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec
- This will leave the RPM in rpmbuild/RPMS/x86_64

To create a deb for Debian or Debian-based distros:
- apt install git tar fakeroot libssl-dev autoconf automake libtool build-essential
- git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
- Run ./ripe-atlas-software-probe/build-config/debian/bin/make-deb
- This will leave the .deb in the current working directory.
