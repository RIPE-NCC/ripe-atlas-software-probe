# FreeBSD specific configuration
RPM_ETC_DIR=$ATLAS_SYSCONFDIR; export RPM_ETC_DIR
BIN_DIR=$ATLAS_SCRIPTS
ATLASINIT=$ATLAS_MEASUREMENT/atlasinit; export REG_INIT_BIN
KNOWN_HOSTS_REG=$ATLAS_DATADIR/known_hosts.reg
REG_SERVERS=$ATLAS_SYSCONFDIR/reg_servers.sh

# FreeBSD specific commands
SET_LEDS_CMD=:
STATIC_V4_CMD=:
STATIC_V6_CMD=:

# FreeBSD specific reboot function
reboot_probe()
{
	# FreeBSD reboot command
	/sbin/reboot
}
