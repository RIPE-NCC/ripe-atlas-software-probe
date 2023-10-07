RIPE Atlas Software Probe
=========================

This is the source code for RIPE Atlas software probes. Currently this
source code supports building an RPM package for CentOS 7 and CentOS 8,
as well as various Debian versions and Debian-based distributions. See
INSTALL.rst for installation instructions.

Unless specified otherwise, this code is licensed under the GPLv3. A
copy of the license can be found in LICENSE.

Note
----

The software probe uses TCP ports 2023 and 8080 internally. If another
service is using these ports, then the probe will not function
correctly. To avoid conflicts, the runtime configuration options
described below are available to make the probe use different port
numbers.

Runtime Configuration Options
-----------------------------

Currently there are three runtime configuration options available. To
use them, create the file /var/atlas-probe/state/config.txt and add a
line per desired configuration setting as per the following:

- Set 'RXTXRPT=yes' to enable sending of interface traffic statistics as
  Atlas measurement results.
- Set TELNETD_PORT to an integer value to make the probe use that TCP
  port number instead of 2023, e.g., 'TELNETD_PORT=52023'.
- Set HTTP_POST_PORT to an integer value to make the probe use that TCP
  port number instead of 8080, e.g., 'HTTP_POST_PORT=58080'.
