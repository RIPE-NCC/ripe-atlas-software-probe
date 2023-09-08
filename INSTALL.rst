Installation Instructions
=========================

Picking a release
-----------------
The repository is structured around 3 main branches:
- A master branch which contains production-ready code.
- A testing branch
- A devel(opment) branch
- Ticket branches

The master branch contains the latest production-level code code. The firmware for hardware probes is built from this branch.
The testing branch is a pointer on the master branch that contains code that is being readied for the next production release.
The development branch contains code which is by its nature feature complete, but may not be fully tested yet. This code is merged into the testing branch upon completion and unit testing.
Ticket branches that branch off the development branch contain features or fixes that may or may not work

Any tag which is a number divisable by 10 is a production release (5060, 5070, 5080). Any tag with another number is either a development or a testing release.

When uncertain, always select the master branch.

To create a RPM for RHEL
------------------------

- ``sudo dnf update && dnf install git tar rpm-build openssl-devel autoconf automake libtool make`` << for reverse compatability with Centos7 systems replace ``dnf`` with ``yum``
- ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- ``rpmbuild --bb ripe-atlas-software-probe/rhel/ripe-atlas-probe.spec``
- This will leave the RPM in rpmbuild/RPMS/x86_64
- Then install the probe, 
- ``sudo dnf -y install rpmbuild/RPMS/x86_64/ripe-atlas-common-????.rpm ripe-atlas-probe-????.rpm``

To create a deb for Debian or Debian-based distros
--------------------------------------------------

Currently only tested on Debian 11 and 12 on the x86_64 platform.

- Get the needed tools: ``sudo apt-get update && sudo apt-get -y install git build-essential debhelper libssl-dev autoconf-dev``
- Clone the repo: ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- Build the needed .deb file in the current working directory:
 * ``cd ripe-atlas-software-probe`` << this will change into the root directory of the git repo that you have clone
 * ``git checkout BRANCH`` << if needed (optional)
 * ``git submodule update`` << this will update the submodule within this branch
 * ``dpkg-buildpackage -b -us -uc``deb`` << this will create the package
 * ``cp ../ripe-atlas-*.deb .``
- Install these .deb files: ``sudo dpkg -i ripe-atlas-common-????.deb ripe-atlas-software-probe-????.deb``

Common installation instructions
--------------------------------
- The public key is stored in ``/etc/ripe-atlas-probe/probe_key.pub``
- Then register your probe at https://atlas.ripe.net/apply/swprobe/

Updating the software probe
---------------------------

As of release 5080, the CentOS RPM will no longer automatically update.
The intent of this decision is to conform to operational practices and to
make deployment and maintenance easier on hosts (and the Atlas team) in the
long run.

If you wish to automatically keep your software probe package up to date, please
install an appropriate tool.

Suggested solutions available are yum-cron (CentOS 7) and dnf-automatic (Redhat
or Redhat clones version 8 and newer).
