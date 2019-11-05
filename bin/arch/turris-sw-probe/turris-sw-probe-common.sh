
WRT_PROBE_SCRIPTS_DIR=/usr/libexec/atlas-probe-scripts
WRT_BASE_DIR=/usr/libexec/atlas-probe; export WRT_BASE_DIR
WRT_ETC_DIR=$WRT_PROBE_SCRIPTS_DIR/etc; export WRT_ETC_DIR
BIN_DIR=$WRT_PROBE_SCRIPTS_DIR/bin
ATLASINIT=$BB_BIN_DIR/atlasinit; export REG_INIT_BIN
KNOWN_HOSTS_REG=$WRT_ETC_DIR/known_hosts.reg
REG_SERVERS=$BASE_DIR/bin/reg_servers.sh

# Commands
SET_LEDS_CMD=log_status

log_status()
{
	state="$1"
	date_now="$(date +'%D %H:%M:%S')"
	echo "$date_now $state" >>/tmp/log/ripe_sw_probe
}
