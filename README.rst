RIPE Atlas Software Probe
=========================

This is the source code for RIPE Atlas software probes. Currently this
source code supports building:
- RPM package for CentOS 8, Oracle EL9, Rocky Linux 9
- DEB package for Debian 11/12
- OpenWRT package for OpenWRT 22.03
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

The public key is stored in ``/etc/ripe-atlas-probe/probe_key.pub``. Use
this to register your probe at <https://atlas.ripe.net/apply/swprobe/>.
