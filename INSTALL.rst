Installation Instructions
=========================

To create a RPM for CentOS 7 or CentOS 8:

- yum install git tar rpm-build openssl-devel autoconf automake libtool make
- git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git
- Run ripe-atlas-software-probe/build-config/centos/bin/make-tars
  (this will create a directory called rpmbuild)
- Run rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec
- This will leave the RPM in rpmbuild/RPMS/x86_64
