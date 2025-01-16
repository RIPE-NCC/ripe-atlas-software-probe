=========================
Installation Instructions
=========================

Picking a release
=================

The repository is structured around 3 main branches, and a topic branch:

- A master branch which contains production-ready code.
- A testing branch
- A devel(opment) branch
- Ticket branches

The master branch contains the latest production-level code. The firmware for hardware probes is built from this branch.
The testing branch is a pointer on the master branch that contains code that is being readied for the next production release.
The development branch contains code which is by its nature feature complete, but may not be fully tested yet. This code is merged into the testing branch upon completion and unit testing.
Ticket branches that branch off the development branch contain features or fixes that may or may not work.

Any tag which is a number divisible by 10 is a production release (5060, 5070, 5080). Any tag with another number is either a development or a testing release.

When uncertain, always select the master branch.

To build RPMs for RHEL-based distributions
==========================================

The build process is performed using ``rpmbuild``.
Currently tested on Oracle Enterprise Linux 8, Oracle Enterprise Linux 9 and Rocky Linux 9 on the x86_64 platform.

- (using root privileges) ``dnf update && dnf install git tar rpm-build openssl-devel autoconf automake libtool make``
- ``git clone https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- ``cd ripe-atlas-software-probe``
- ``rpmbuild --bb rhel/ripe-atlas-probe.spec`` (see note)
- ``rpmbuild --bb rhel/ripe-atlas-anchor.spec`` (see note)
- ``cd .repo``
- ``rpmbuild --bb rhel/ripe-atlas-repo.spec`` (see note)

NOTE: if you wish to build specific (development) branches or repositories:

* ``git_source``; to specify a GIT repository (``--define "git_source https://github.com/RIPE-NCC"``)
* ``git_tag``; to specify a particular version (``--define "git_tag 5080"``)
* ``git_commit``; to specify a particular commit (``--define "git_commit abcdef"``)

This will leave the RPMs in ``rpmbuild/RPMS/x86_64`` and ``rpmbuild/RPMS/noarch``.

To install RPMs for RHEL-based distributions
============================================

NOTE: The ripe-atlas-anchor package is intended for deploying Atlas
      anchors. Please **only** install when instructed to do so by RIPE
      NCC staff.

Automatic Updates
-----------------
As of release 5080, the RPM will no longer automatically update.

The intent of this decision is to conform to operational practices and to
make deployment and maintenance easier on hosts (and the Atlas team).
If you wish to keep automatically updating your software probe, please
install the automatic update package of your choice.

Suggested solutions available are yum-cron, dnf-automatic or unattended-upgrades.

Offline (locally built)
-----------------------

To install, execute:

- ``cd ~/rpmbuild/RPMS``
- (using root privileges) ``dnf -y install x86_64/ripe-atlas-common-????-1.el?.x86_64.rpm noarch/ripe-atlas-probe-????-1.el?.noarch.rpm``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

Online (built by RIPE NCC)
--------------------------

To install, execute:

- (using root privileges on el8) ``dnf -y install https://ftp.ripe.net/ripe/atlas/software-probe/el8/noarch/ripe-atlas-repo-1.5-2.el8.noarch.rpm``
- (using root privileges on el9) ``dnf -y install https://ftp.ripe.net/ripe/atlas/software-probe/el9/noarch/ripe-atlas-repo-1.5-2.el9.noarch.rpm``
- (using root privileges) ``dnf -y install ripe-atlas-probe``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

To upgrade RPMs from atlasswprobe
---------------------------------

Upgrading from atlasswprobe will attempt to migrate existing
probe keys and configuration.

Existing probe state will be removed (``/var/atlas-probe``).

Offline (locally built)
^^^^^^^^^^^^^^^^^^^^^^^

To upgrade on EL8, execute:

- ``cd ~/rpmbuild/RPMS``
- (using root privileges) ``dnf -y install noarch/ripe-atlas-common-????-1.el8.noarch.rpm``
- (using root privileges) ``dnf -y upgrade x86_64/ripe-atlas-probe-????-1.el8.x86_64.rpm``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

Online (built by RIPE NCC)
^^^^^^^^^^^^^^^^^^^^^^^^^^

To upgrade on EL8, execute:

- (using root privileges) ``dnf -y upgrade https://ftp.ripe.net/ripe/atlas/software-probe/el8/noarch/ripe-atlas-repo-1-5.el8.noarch.rpm``
- (using root privileges) ``dnf -y install ripe-atlas-probe``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

To build DEB files for Debian or Debian-based distributions
===========================================================

The build process is performed using dpkg-buildpackage (compat version 13).
Currently tested on Debian 11 and 12 on the x86_64 platform.

- Get the needed tools (using root privileges): ``apt-get update && apt-get -y install git build-essential debhelper libssl-dev autotools-dev psmisc net-tools``.
- Clone the repo: ``git clone https://github.com/RIPE-NCC/ripe-atlas-software-probe.git``
- Build the needed .deb file in the current working directory:

 * ``cd ripe-atlas-software-probe`` (root dir of git repo)
 * ``git checkout BRANCH`` (optional)
 * ``dpkg-buildpackage -b -us -uc`` << this will create the package
 * ``cp ../ripe-atlas-*.deb .``
 * ``cd .repo``
 * ``dpkg-buildpackage -b -us -uc`` << this will create the repository package

To install DEB files for Debian or Debian-based distributions
=============================================================

NOTE: The ripe-atlas-anchor package is intended for deploying Atlas
      anchors. Please only install when instructed to do so by RIPE
      NCC staff.

Offline (locally built)
-----------------------

To install, execute:

- (using root privileges): ``dpkg -i ripe-atlas-common_????_amd64.deb ripe-atlas-probe_????_all.deb``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

Online (built by RIPE NCC)
--------------------------

To install, execute:

- (on debian11) ``wget https://ftp.ripe.net/ripe/atlas/software-probe/debian/dists/bullseye/main/binary-amd64/ripe-atlas-repo_1.5-2_all.deb``
- (on debian12) ``wget https://ftp.ripe.net/ripe/atlas/software-probe/debian/dists/bookworm/main/binary-amd64/ripe-atlas-repo_1.5-2_all.deb``
- (using root privileges) ``dpkg -i ./ripe-atlas-repo_1.5-2_all.deb``
- (using root privileges) ``apt-get update``
- (using root privileges) ``apt-get install ripe-atlas-probe``
- (using root privileges) ``systemctl enable ripe-atlas.service``
- (using root privileges) ``systemctl start ripe-atlas.service``

Note that packages have been signed and can be verified using ``debsigs``,
for example:
``debsig-verify ./ripe-atlas-probe_????_amd64.deb``

This can only be done after the ripe-atlas-repo package has been installed.

To build IPKG files for OpenWRT
===============================

The build process is performed using OpenWRT's build process.
Currently compile tested on OpenWRT 22.03. OpenWRT 22.03 will be
fully supported in an upcoming release.

The package can be added to the build by adding the line:
``src-git ripe-atlas git@github.com:RIPE-NCC/ripe-atlas-software-probe.git``
and running:
``scripts/feeds install -a``
from the toplevel OpenWRT directory.

The branch checked out is master, other branches can be checked out by appending ;<BRANCH> or ^commit to the line in feeds.conf.

After adding the package can be selected using menuconfig and built as normal.

To install IPKG files for OpenWRT
=================================

To install, execute:

- ``opkg install ripe-atlas-common-????.ipkg ripe-atlas-software-probe-????.ipkg``
- ``service ripe-atlas start``

Manual build
============================

To build using autoconf tooling and install the software probe, execute the following commands at the top level of the git repo:

- ``autoreconf -iv``
- ``./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib64 --runstatedir=/run --with-user=ripe-atlas --with-group=ripe-atlas --with-measurement-user=ripe-atlas-measurement --disable-systemd --enable-chown --enable-setcap-install``
- ``make``

Manual installation
===================

To install, execute:

- (using root privileges) ``make install``
- (using root privileges) ``/usr/sbin/ripe-atlas``
