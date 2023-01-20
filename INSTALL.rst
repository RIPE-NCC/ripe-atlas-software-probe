Installation Instructions
=========================

To create a RPM for CentOS 7 or CentOS 8
----------------------------------------

- ``sudo yum update && yum install git tar rpm-build openssl-devel autoconf automake libtool make``
- ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- ``ripe-atlas-software-probe/build-config/centos/bin/make-tars``
  (this will create a directory called rpmbuild)
- ``rpmbuild --bb rpmbuild/SPECS/atlasswprobe.spec``
- This will leave the RPM in rpmbuild/RPMS/x86_64
- Then install the probe, 
- ``sudo dnf -y install rpmbuild/RPMS/x86_64/atlasswprobe*``
- The public key can be found by using 
- ``cat /var/atlas-probe/etc/probe_key.pub``
- Then register your probe at https://atlas.ripe.net/apply/swprobe/

To create a deb for Debian or Debian-based distros
--------------------------------------------------

Currently only the Debian Build system includes support for amd64, arm64, and armhf.

- Get the needed tools: ``sudo apt update && sudo apt install git tar fakeroot libssl-dev libcap2-bin autoconf automake libtool build-essential``
- Clone the repo: ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- Build the needed .deb file in the current working directory: ``./ripe-atlas-software-probe/build-config/debian/bin/make-deb``
(Please note if you are running Ubuntu it may be required to checkout the devel branch of this repo. If this is the case and the .deb build does not complete without failing this is the command sequence to follow before trying the install of the .deb);
 * ``cd ripe-atlas-software-probe`` << this will change into the root directory of the git repo that you have clone
 * ``git checkout devel`` << this will checkout the DEVEL branch instead of the MASTER branch
 * ``git submodule update`` << this will update the submodule within this branch
 * ``cd ..`` << this take you back to where you started
 * ``./ripe-atlas-software-probe/build-config/debian/bin/make-deb`` << this will retry the build 
- Install this .deb file: ``sudo dpkg -i atlasswprobe-??????.deb``
- The public key is stored in ``/var/atlas-probe/etc/probe_key.pub``
- Then register your probe at https://atlas.ripe.net/apply/swprobe/

Updating the software probe
---------------------------

As of release 5080, the CentOS RPM will no longer automatically update.
The intent of this decision is to conform to operational practices and to
make deployment and maintenance easier on hosts (and the Atlas team) in the
long run.

If you wish to keep automatically updating your software probe, please install the
automatic update package of your choice.

Suggested solutions available are yum-cron, dnf-automatic or unattended-upgrades.
