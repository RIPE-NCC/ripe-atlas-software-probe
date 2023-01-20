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
