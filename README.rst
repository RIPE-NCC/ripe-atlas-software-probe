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

Release strategy
---------------

When selecting which code to build, keep in mind:
* Anything in the master branch should be considered production code
* Any tag divisible by 10 is a production release (but may not be the
  latest one)
* Any other tag or branch is a development or testing release

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

The build process is performed using 'rpmbuild' for RHEL. By default the build is based on the master HEAD. Command-line defines can be set for branch and commits in order to specify specific build points. Currently two are supported

- git_tag
- git_commit

The arguments are specified in a define flag in the 'rpmbuild' command. For example if a user wants to build the repo RPM from a specific commit on the master branch then use the following command:

`rpmbuild -bb --define "git_commit 32c5747" ripe-atlas-software-probe/build-config/generic/ripe-atlas-repo.spec`

If a specific version is to be build then:

`rpmbuild -bb --define "git_tag 5090"  ripe-atlas-software-probe/build-config/generic/ripe-atlas-repo.spec`

Note that build outputs will still result in '~/rpmbuild' unless otherwise specified
