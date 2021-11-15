Release History
===============

5040 (released 2021-10-21)
--------------------------
- Measurement changes (version 2.4.1):

  * Firmware 5030 introduced a regression where a specific type of TCP connect failure would cause the probe to stop performing measurements.

5030 (released 2021-09-13)
--------------------------
- Config variable to disable the check that atlas data is on tmpfs
- Support for software probes on OpenWrt (by Jan Pavlinec)
- Measurement changes (version 2.4.0):

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
- Use the hash of the public key in sos messages for virtual probes and anchors
- Fix bug in dns measurements where a json field gets duplicated (measurement busybox 2.2.1)
- Suppress some debug output from dfrm (measurement busybox 2.2.1)
- Make response to a reg. server returning WAIT more robust

5010 (released 2020-01-13)
---------------------------
- Support for Turris routers
- Build fixes for CentOS 8
- Improved mechanism to source architecture specific scripts
- Removed some bash-isms
- Support Debian
- Measurement changes (version 2.2.0):

  * "qt" field for DNS measurements to report query time without setup overhead
  * Handle IPv6 scope IDs
  * Switch to libevent 2.1.11
  * 'httppost' should only set the system if the environment variable HTTPPOST_ALLOW_STIME is set
  * Add '--ttl' option to DNS measurements


5000.2 (released 2019-10-07)
---------------------------
- Make setting the time and date in the ATLAS script optional
- Corrected names of production registratoin servers
- Introduce config.txt to make rxtxrpt optional
- Add -y option to yum update
- Added README.rst, INSTALL.rst, CHANGES.rst and LICENSE

5000 (released 2019-10-01)
--------------------------
- Initial release
