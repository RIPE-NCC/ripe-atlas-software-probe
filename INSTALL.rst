Installation Instructions
=========================

To create a RPM for CentOS 7:

- Check out this repo in a directory called ripe-atlas-software-probe
  on a system running CentOS 7.
- Run ripe-atlas-software-probe/build-config/centos/bin/make-tars
  (this will create a directory called rpmbuild)
- Run rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec
- This will leave the RPM in rpmbuild/RPMS/x86_64
