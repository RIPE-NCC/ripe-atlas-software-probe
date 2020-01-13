Release History
===============

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
