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

To build RPMs for RHEL-based distros
------------------------------------

- ``sudo dnf update && dnf install git tar rpm-build openssl-devel autoconf automake libtool make`` << for reverse compatability with Centos7 systems replace ``dnf`` with ``yum``
- ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- cd ripe-atlas-software-probe
- ``rpmbuild --bb rhel/ripe-atlas-probe.spec``, see note.
- ``rpmbuild --bb rhel/ripe-atlas-anchor.spec``, see note.
- NOTE: if you wish to build specific (development) branches or repositories:
  * git_source; to specify a GIT repository (--define "git_source https://github.com/RIPE-NCC")
  * git_tag; to specify a particular version (--define "git_tag 5080")
  * git_commit; to specify a particular commit (--define "git_commit abcdef")
- This will leave the RPMs in rpmbuild/RPMS/x86_64
- To install, ``sudo dnf -y install rpmbuild/RPMS/x86_64/ripe-atlas-common-????.rpm ripe-atlas-probe-????.rpm``

To build DEB files for Debian or Debian-based distros
-----------------------------------------------------

The build process is performed using dpkg-buildpackage (compat version 13).
Currently only tested on Debian 11 and 12 on the x86_64 platform.

- Get the needed tools: ``sudo apt-get update && sudo apt-get -y install git build-essential debhelper libssl-dev autoconf-dev``. Note that ``autoconf-dev`` may be ``autotools-dev`` on very recent Debian systems
- Clone the repo: ``git clone --recursive https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- Build the needed .deb file in the current working directory:
 * ``cd ripe-atlas-software-probe`` << this will change into the root directory of the git repo that you have clone
 * ``git checkout BRANCH`` << if needed (optional)
 * ``git submodule update`` << this will update the submodule within this branch
 * ``dpkg-buildpackage -b -us -uc`` << this will create the package
 * ``cp ../ripe-atlas-*.deb .``
- To install, ``sudo dpkg -i ripe-atlas-common-????.deb ripe-atlas-software-probe-????.deb``

To build IPKG files for OpenWRT
-------------------------------

The build process is performed using OpenWRT's build process. The package can be added to
the build by adding the line:
`src-git ripe-atlas git@github.com:RIPE-NCC/ripe-atlas-software-probe.git`
and running:
`scripts/feeds install -a`
from the toplevel OpenWRT directory.

The branch checked out is master, other branches can be checked out by appending ;<BRANCH> or ^commit to the line in feeds.conf.

After adding the package can be selected using menuconfig and built as normal.

To install, use ``opkg install ripe-atlas-common-????.ipkg ripe-atlas-software-probe-????.ipkg``

Manual installation
-------------------

To build using autoconf tooling and install the software probe, execute the following commands at the top level of the git repo:

- ``autoreconf -iv``
- ``./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib64 --runstatedir=/run --with-user=ripe-atlas --with-group=ripe-atlas --with-measurement-user=ripe-atlas-measurement --enable-systemd --enable-chown --enable-setcap-install``
- ``make``
- ``make install``
