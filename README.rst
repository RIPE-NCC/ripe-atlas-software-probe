RIPE Atlas Software Probe
=========================

This is the source code for RIPE Atlas software probes. Currently this
source code supports building a RPM package for CentOS 7. See
INSTALL.rst for installation instructions.

Unless specified otherwise, this code is licensed under the GPLv3. A copy
of the license can be found in LICENSE.

Note
----

The software probe uses TCP ports 2023 and 8080 internally. If another
service is using these ports then the probe will not function correctly.

Runtime Configuration Options
-----------------------------

Currently there is one runtime configuration option that enables sending
interface traffic statistics as Atlas measurement results. 
This option can be enabled by creating the file
/var/atlas-probe/state/config.txt and adding the line 'RXTXRPT=yes'.

Autoconf Build
--------------

To build using autoconf tooling and install the software probe to a directory (ie. /tmp/data), execute the following commands at the top level of the git repo (specifically where $(pwd) is /path/to/ripe-atlas-software-probe):

>> autoreconf -iv
>> ./configure --prefix=/usr/local/atlas --localstatedir=/home/atlas
>> make
>> make DESTDIR=/tmp/data install

RPM Build
--------------
The build process is performed using 'rpmbuild' for RHEL. By default the build is based on the master HEAD. Command-line defines can be set for branch and commits in order to specify specific build points. Currently two are supported

- git_tag
- git_commit

The arguments are specified in a define flag in the 'rpmbuild' command. For example if a user wants to build the repo RPM from a specific commit on the master branch then use the following command:

`rpmbuild -bb --define "git_commit 32c5747" ripe-atlas-software-probe/rhel/ripe-atlas-repo.spec`

If a specific version is to be build then:

`rpmbuild -bb --define "git_tag 5090"  ripe-atlas-software-probe/rhel/ripe-atlas-repo.spec`

Note that build outputs will still result in '~/rpmbuild' unless otherwise specified

Three spec files are given each for the following:
- rhel/ripe-atlas-repo.spec -> used to build the package RPM
- rhel/ripe-atlas-anchor.spec -> used to build the Anchor RPM
- rhel/ripe-atlas-probe.spec -> used to build the Probe RPM (if you are building locally this is what you should build)

DEB Build
--------------
The build process is performed using dpkg-buildpackage on Debian 11 or 12 (compat version 13). The build is based on the currently checked out branch.

If a user wants to build a Debian package, use the following commands:
cd ripe-atlas-software-probe; dpkg-buildpackage -b -us -uc

Packages built can be find one directory above the ripe-atlas-software-probe directory.

OpenWRT Build
--------------
The build process is performed using OpenWRT's build process. The package can be added to
the build by adding the line:
`src-git ripe-atlas git@github.com:RIPE-NCC/ripe-atlas-software-probe.git`
and running:
`scripts/feeds install -a`
from the toplevel OpenWRT directory.

The branch checked out is master, other branches can be checked out by appending ;<BRANCH> or ^commit to the line in feeds.conf.

After adding the package can be selected using menuconfig and built as normal.
