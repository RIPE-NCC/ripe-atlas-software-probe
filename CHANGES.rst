Release History
===============

5110 (released 2025-03-26)
--------------------------
- All platforms
  * Updated telnetd.c to add a missing include which caused the probe's compilation to fail in Alpine Linux 3.21 (committed by César de Tassis Filho mailto:ctassisf@gmail.com)
  * The code signing key introduced in release 5100 will as of this release be
used to sign RHEL packages as well. The current RHEL key is therefore deprecated
as of this release
- Software Probes
  * Fixed typo in GitHub org url for RHEL ripe-atlas-anchor specfile (authored by by Pouria Mousavizadeh Tehrani mailto:info@spmzt.net)
  * Fixed typo in GitHub org url for RHEL ripe-atlas-probe specfile (committed by eeple mailto:m.renusson@gmail.com)
  * Hardened the security of the RIPE Atlas service unit (reported by Marek Küthe mailto:m.k@mk16.de)
  * Added missing requirement for procps-ng on RHEL9 to RHEL probe package specfile (committed by Robert Scheck mailto:robert-scheck@users.noreply.github.com)
  * Probe private/public key pair is now generated immediately after installation, without needing the service to start up
  * Probe installation scripts also display registration instructions for RHEL a
nd Debian
  * Debian 12 arm64 support added

5100 (released 2024-09-24)
--------------------------
- All platforms
  * As of this version, the ripe-atlas-probe-measurements repository on GitHub is deprecated. Its code has been merged into the ripe-atlas-software-probe repository
  * Package can now be built with arbitrary shell shebangs. Note that only OpenWRT ash and bash are officially supported
  * Bug fixed where permissions are wrong when systemd is disabled (reported by César de Tassis Filho mailto:ctassisf@gmail.com)
  * A new code signing key has been introduced. It only signs Debian packages currently, but will sign the RHEL packages in an upcoming release as well. The current RHEL key will then be deprecated
- Software probes
  * Streamlined deployment on RHEL CI/CD
  * systemd unit ownership moved to probe and anchor packages
  * Debian 11/12 x86_64 support added

5090 (released 2024-07-12)
--------------------------
- All platforms
  * All platforms now have a ripe-atlas-common package, a ripe-atlas-anchor and ripe-atlas-probe package to define the purpose of the probe. This deprecates atlasswprobe
  * Package is now built using autotools
  * Package restructured according to Linux FHS
  * Probe private key is not removed upon uninstall
  * libevent is now linked to the measurement code statically. It diverged from the original package and cannot be sent upstream
  * sudo is no longer required, the processes drop privileges automatically
- Software probes
  * Added support for Oracle EL8 and RHEL9 (Oracle EL9 / Rocky Linux 9)
  * Added initial code for Debian 11/12 (Support incomplete)
  * Added initial code for OpenWRT 22.03 (Support incomplete)
  * Fix Atlas not working on SELinux (RHBA-2023:5062); Robert Scheck
  * Sanitised log messages (unnecessary errors)
  * Probe sub architecture now reports ID, VERSION and PLATFORM
  * systemd-sysusers and systemd-tmpfiles now used
  * Atlas now exits properly when stopped by systemd on EL8
  * Bash is now a requirement
  * RPM now validates properly

5080 (released 2022-09-23)
--------------------------
- All platforms
  * Introduction of CI/CD pipeline for building firmware
  * Fix for ICMPv6 echo replies on systems with 32-bit pid_t (Graham Edgecombe)
- Software probes
  * The auto update functionality has been removed from the CentOS 7/8 RPM.
- Cleanup on v3 hardware probe to align with v4 and v5 probes.
  * Streamline build process for flash and USB firmware
  * Removal of unused software / functionality
  * Revert to stock OpenWRT insofar as possible
  * Code refactoring to remove duplicate implementation of LED behaviour
  * JSON style logging framework introduced, initially for process restarting
  * Filesystem bug fixed that prevented release of flash firmware

5070 (released 2022-05-31)
--------------------------
- Fix bug that caused processes to restart erroneously.
- Added support for NTP size extension (by Daniel Drown)

5060 (released 2022-03-16)
--------------------------
- Removed IPv6 reporting from rxtxrpt
- Replace syscall(__NR_clock_gettime, ...) with clock_gettime() (by Eneas U de Queiroz)
- Fix rptaddrs to handle systems without IPv6. Sad but true.
- Allow measurement targets to be in the prefixes 0.0.0.0/8 and 240.0.0.0/4
- Add HTTPPOST_PORT port override for httppost
- Improvements for self tests
- Updated cipher list in sslgetcert to Firefox 89.0.2
- Support for DNS-over-HTTPS measurements

5050 (released 2022-02-16)
--------------------------
- This is an administrative release, it does not have any changes.

5040 (released 2021-10-21)
--------------------------
- Measurement changes (version 2.4.1):
  * Firmware 5030 introduced a regression where a specific type of TCP connect failure would cause the probe to stop performing measurements.

5030 (released 2021-09-13)
--------------------------
- Config variable to disable the check that atlas data is on tmpfs
- Support for software probes on OpenWrt (by Jan Pavlinec)
- Measurement busybox v2.4.0:
  * Solve issue with duplicate src_addr in DNS measurements
  * Remove as much as possible source files that are not used by Atlas
  * Fix bug in sslgetcert if there is a connection failure
  * Replace stime with clock_settime
  * Support a lot more network interfaces in reporting traffic statistics
  * Option to set AD bit in DNS queries
  * Initial support for testing Atlas measurement code

5020 (released 2020-04-06)
--------------------------
- Support for a centos 8 binary repo
- Use the hash of the public key in SOS messages for software probes and anchors, allowing software probes to report SOS messages
- Fix a bug in DNS measurements where a JSON fields got duplicated (measurement busybox 2.2.1)
- Suppress some debug output from dfrm (measurement busybox 2.2.1)
- Make response to a reg. server returning WAIT more robust

5010 (released 2020-01-13)
--------------------------
- Support for Turris routers
- Support Debian
- Build fixes for CentOS 8
- Improved mechanism to source architecture specific scripts
- Support for DNS resolvers with IPv6 link local address
- Removed some bash-isms
- Measurement changes (version 2.2.0):
  * "qt" field for DNS measurements to report query time without setup overhead
  * Handle IPv6 scope IDs
  * Switch to libevent 2.1.11
  * 'httppost' should only set the system if the environment variable HTTPPOST_ALLOW_STIME is set
  * Add '--ttl' option in DNS measurements to report the TTL on replies (for UDP)

5000 (released 2019-10-07)
--------------------------
- Probe firmware 5000.2
  * Make setting the time and date in the ATLAS script optional
  * Corrected names of production registration servers
  * Introduce config.txt to make rxtxrpt optional
  * Add -y option to yum update
  * Added README.rst, INSTALL.rst, CHANGES.rst and LICENSE
- Probe firmware 5000
  * First release of software probes - sync up probe firmware versions between hardware and software

4980 (released 2019-04-10)
--------------------------
- Disable TCP SACK

4970 (released 2019-03-25)
--------------------------
- Fixed an issue with periodic HTTP measurements and a chunked response from the remote server
- Generate a new value for the "$r" macro in DNS measurements for each resolver when "use probe's resolvers" is in effect
- Fixed a bug in TCP traceroute when some measurements did not run if there were more than 256 measurements defined

4960 (released 2019-02-26)
--------------------------
- Fix local time management to deal with cases where the probe did not adjust its local time correctly
- Add support for reinstalling the current firmware if (filesystem) corruption is suspected

4950 (released 2019-02-20)
--------------------------
- Fixed a bug in traceroute where a trace was supposed to stop after 5 non-responding hops, but it stopped earlier if the starting hop was not set to 1
- Added support for DNS cookies (API/UI support is in the works)
- Added support to set EDNS version, flags and options (API/UI support TBD)
- Added support to send DNS queries with IPv6 destination option (API/UI support is in the works)
- Code shuffles to record timestamps for response time as close as possible to sending and receiving calls

4940 (released 2018-07-17)
--------------------------
- Add support for DNS client subnet option
- Add support for HTTP host header
- Add support for ping synchronous DNS resolution (only used internally)
- Update SSL/TLS list of ciphers (taken from wget 1.19.1)
- Add support for SSL/TLS elliptic curves
- Add better error reporting for TLS errors
- Add support for traceroute ToS
- Internal code changes to align the behaviour/scripts used on v3 and v4 probes
- Fix a bug where probes no longer sent DNS "sos" queries

4930 (released 2018-05-21)
--------------------------
- This firmware is a clone of 4910, aimed exclusively for the upcoming v4 probes

4910 (released 2018-01-08)
--------------------------
- General
  * Upgrade busybox (used inside the probe firmware)
  * When name resolution results in a 'local' address and the probe denies executing the measurement, report the offending address
  * Report how long name resolution takes (except for DNS measurements)
  * SSL/TLS certificate measurements now report the cipher that is chosen by the server
  * Fix bug where a TCP socket was not set to non-blocking when explicit binding to an interface was required
- Anchor
  * Support added for CentOS 6 and 7

4790 (released 2017-05-29)
--------------------------
- This is a v1/v2 only release meant to fix stability issues that resulted in stretching the hardware capabilities too far.

4780 (released 2017-05-22)
--------------------------
- Various fixes for stability and security
- Allow DNS "macros" like $p, $t, $r, which are replaced by the probe each time with probe ID, timestamp and a random value, respectively
- Add SNI support to TLS/SSL checks
- Add option to embed probe ID in ping requests in order to filter out RIPE Atlas generated ICMPs
- Report time-to-complete in TLS/SSL results even if fetching the actual certificate fails
- Fixed a bug where there were no results delivered for DNS measurements with the "include the abuf" option turned off

4770 (released 2017-03-22)
--------------------------
- Fixed a regression where DNS measurements using TCP transport always failed
- Fixed a bug where WiFi measurements could sometimes report using the wrong outgoing network interface

4760 (released 2017-02-23)
--------------------------
- Changes to use USB sticks (in v3 probes) as little as possible by buffering results in memory. As a tradeoff for more expected stability, the probes lose recent, unreported measurement results (ie. the ones collected in the last 60-90 seconds).
- Unexpectedly terminated TCP connections caused SIGPIPE signals crashing the measurement the process
- Various stability and security fixes to the measurement code

4750 (released 2017-01-24)
--------------------------
- First release of wifi firmware (4755)
- Various security/stability fixes in the measurement code

4740 (released 2016-08-08)
--------------------------
- Disallow measurements towards 0.0.0.0/8
- Internal changes to support wifi measurements
- Report local network configuration every hour
- Switch to ext4 filesystem for USB storage
- Check for read-only USB and send SOS message if that's the case
- Fixed kernel to not download new firmware if the usb stick is read-only

4730 (released 2016-01-18)
--------------------------
- Better error handling for unexpected measurement results
- Probes will soon start reporting their uptime in a new "virtual measurement", ID 7001
- Fixed an error case where  results of one-off traceroutes could have interfered with ongoing traceroutes
- Added preliminary support for specifying a timeout parameter for DNS measurements

4720 (released 2015-10-05)
--------------------------
- The method for measuring times (e.g. RTTs) for each measurement has been switched to use a strictly monotonic, relative clock, thereby avoiding the artefacts caused by absolute clock changes due to time synchronisation.
- The RDATA field of a DNS measurement result (in response to a TXT query) is now a list of strings. It was a single string before.
- The cipher list supported by SSL/TLS certificate checks have been refreshed.
- Fixed a bug where one-off results were reported multiple times in some cases.
- Fixed a issue where NTP measurements could generate syntactically incorrect results which, as a consequence, were never stored.
- Fixed an issue where IPv6-only probes did not properly report their network configuration.
- Fixed a bug where failed DNS measurements in some cases did not report the time of measurement.
- The probes, in addition to the infrastructure, now also enforce the restriction that local (RFC1918 and link-local) addresses should not be measured.
- When removing static configuration from a probe, the statically added previous DNS server was still used

4700 (released 2015-07-06)
--------------------------
- This is mostly a maintenance release, with internal behavioural changes only.

4680 (released 2015-03-28)
--------------------------
- This firmware incorporates a few bug fixes:
- If probe has statically configured nameserver and also DHCPv4, the DHCP one wins, thereby fixing stale DNS entries
- Enhance the NTP client on v3 probes
- V3 probes now pick up IPv6 DNS resolvers from RA messages
- Stability issues on v1/v2 probes when HTTP measurements immediately fail with connection errors
- "SSLCert" measurements now also support TLS

4670 (released 2015-01-14)
--------------------------
- Fixed two bugs in ping measurements where the probe had issues pinging its own IPv6 address
- Fixed wrong host header for IPv6 literals in http measurements
- Probes are now trying to avoid starting too many measurements at exactly the same second

4660 (released 2014-08-25)
--------------------------
- Bugfix: fixed a bug in paris traceroute where the ICMP version would have the wrong paris id in outgoing packets
- Bugfix: fixed a memory leak in the DNS measurements code
- Enhancement: include a cookie in outgoing ping packets and check the reply
- Enhancement: in ping, report IP version and target address even if socket connect fails
- Experimental suport for NTP measurements (not publicly available yet)

4650 (released 2014-07-08)
--------------------------
- Ping interval option (-i option, needs support from API and UI)
- The "lts" field is now also available in the output of traceroute, dns, sslgetcert, httpget
- Traceroute IPv6 extra error code 'h': destination unreachable/beyond scope
- Fixed error in the output of traceroute
- Fixed bug in parsing multiple IPv6 extension headers in traceroute
- Fixed bug in DNS where RA flag was set in requests

4610 (released 2014-03-17)
--------------------------
- The new firmware fixes a few DNS related bugs:
- In some cases the probe sent DNS results too often
- Querying the local DNS resolver could result in multiple results (one per resolver), but these could not be accessed in the data store. The new version collects results from all resolvers into one data structure. See the /apis/result-format/#version-4610-dns-lookup for details.
- In addition, this firmware adds preliminary support for using IPv6 extension headers. This will be available in the UI and in the API at a later date.

4600 (released 2014-02-17)
--------------------------
- The new firmware release (4600) contains bug fixes for missing fields in ping results (TTL and source address). It also incorporates a more secure way for the probes to authenticate new firmwares before upgrading.

4580 (released 2013-12-16)
--------------------------
- Due to an issue with the latest firmware release, a subset of the v3 probes were listening to incoming connections on an open port that should not have been left open. As a secondary measure, however, access to this port required credentials only available to the RIPE Atlas probe developers. It therefore never presented open access to the probes. This port (SSH) is used for development purposes in our internal development environment.
- We upgraded the v3 probes to a new, corrected firmware version (4580), and improved the checks in our firmware release process. The new firmware is otherwise functionally equivalent to the previous one.
- This issue did not affect version 1/2 probes and anchors.

4570 (released 2013-11-21)
--------------------------
- Upgrade kernel on v3 probes without losing static network config
- Uniform interpretation of the size parameter of ping and traceroute: the size excludes the IPv4/IPv6 header and the transport (ICMP, TCP, UDP) header
- Add TCP mode to traceroute measurements
- Most measurements (except for DNS "use probe's local resolvers") now pick up a new list of resolvers if it has been updated by DHCP
- Support for SRV and NAPTR in DNS measurements
- Support "number of retries" option in DNS measurements
- Note that the use of the new measurement flag will be enabled in the UI and API at a later stage.

4520 (released 2013-04-23)
--------------------------
- This is a bug fix release for all probe architectures. There is a small bug in the probe measurement code that can be trigger only if a controller sends the wrong commands to a probe.

4510 (released 2013-04-23)
--------------------------
- Version 3 probes
  * Fixes for static network configuration
- Anchor
  * Cleanup in anchor package
  * Various fixes to the startup/shutdown scripts
  * Aligned build script with upstart for killing processes
  * Clean up pid files on Atlas shutdown
  * Kill Atlas processes on install/uninstall
  * Anchor now requires daemontools to be installed

4500 (released 2013-02-28)
--------------------------
- RIPE Atlas probe software now supports two more architectures: TP-Link (for the next generation probes) and CentOS (for RIPE Atlas anchors).
- There is now support for one-off measurements for ping, traceroute, DNS, and HTTPget.
- We fixed a bug in DNS measurements in which, when querying local resolvers, more queries went to the last resolver.
- Fixed "error" : { "TUCONNECT" : "Success"}. Before this version DNS TCP and HTTPget reported an error message "Success".
- First release of anchor package

4480 (released 2012-10-03)
--------------------------
- Fixed bug in traceroute when it has to deal with rfc4884 objects (mpls) that have a wrong size.
- Delayed DNS name resolution in ping and traceroute. This feature will soon be enabled through the UI.
- Fixed bug in HTTP GET where some characters where not properly escaped in generating the result JSON.
- Fixed bugs in the libevent stub resolver to better handle DNS errors and timeouts (affects mostly httpget)
- Limit the amount of measurement data that is sent as one unit. This prevents probes that have not connected to a controller for some time from overloading the controller.
- The probe uptime is now in the DNS SOS messages that are sent by probes before they try to connect. This will allow making a distinction between various reasons for disconnects: e.g. probe reboot vs. network problems.
- Initial version for anchor package added (Anand Buddhev)

4470 (released 2012-09-20)
--------------------------
- This firmware fixes two bugs.
  * The first one is that DNS results may get mixed up when a probe runs two DNS measurements at the same time.
  * The second one is where traceroute sometimes reports a timestamp of 0.
- In addition, the firmware now has IPv6 literals for the registrations servers, so an IPv6-only probe can connect to a registration server even if it doesn't have a DNS resolver.

4460 (released 2012-06-21)
--------------------------
- The main new feature in this firmware is the use of libevent and rewriting the measurement code to use it. This provides a much higher capacity for doing measurements. In addition, the probe now reports results in JSON. Expect the traceroute output to be completely different. The are a number of small changes. For example, the DHCP client now sets the client-id and vendor class. Please note that if you have given the probe a static IPv4 address through DHCP and the probes stops working then this may be caused by the change in DHCP client-id.

4310 (released 2012-02-22)
--------------------------
- This firmware contains a number of small fixes that deal with exceptional conditions. Probes should also reconnected slightly quicker after a disconnect.

4270 (released 2011-10-10)
--------------------------
- More pings to fixed destinations
- Traceroutes to fixed destinations
- DNS root server anycast instance checks

4030 (released 2011-07-04)
--------------------------
- We're in the process of rolling out a new firmware version. It enables a new feature that has been asked by members of the community: /howtos/probe-static-network-config.md. Using the UI, one can ask the probe to try to use static IPv4/IPv6 addresses (and DNS resolvers). If these settings don't work, the probes will fall back to using DHCP. As a byproduct, this feature also allows IPv6-only deployments.

4020 (released 2011-02-07)
--------------------------
- The new firmware version enables the use of a second registration server (woolsey.atlas.ripe.net). All probes are expected to upgrade automatically in the coming days.

