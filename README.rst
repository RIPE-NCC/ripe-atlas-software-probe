RIPE Atlas Software Probe
=========================

This is the source code for RIPE Atlas software probes. Currently this
source code supports building:

- RPM package for Oracle EL8 (RHEL8), Oracle EL9 / Rocky Linux 9 (RHEL9)
- DEB package for Debian 11/12
- OpenWRT package for OpenWRT 22.03

Of the supported builds, the RPM and DEB packages have received
sufficient testing. OpenWRT should be considered Beta quality and will be
fully supported in an upcoming release.

See INSTALL.rst for installation instructions.

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
/etc/ripe-atlas/config.txt and adding the line 'RXTXRPT=yes'.

Common installation instructions
--------------------------------

The public key is stored in ``/etc/ripe-atlas/probe_key.pub``. Use
This to register your probe at <https://atlas.ripe.net/apply/swprobe/>.
