# Files
LEDS_KERNEL='tp-link:green:3g'
LEDS_FIRMWARE='tp-link:green:wlan'
LEDS_NETWORK='tp-link:green:lan'
LEDS_SPARE='tp-link:green:wps'

# Commands
SET_LEDS_CMD=set_leds_tplink_mr3020
BUDDYINFO=do_buddyinfo

# Config
IPV6_INF="br-lan"

set_led()
{
	local led="${1}"
	local ledpath="/sys/class/leds/${led}"
	local on="${2}"
	local off="${3}"
	local trigger
	local brightness
	
	if [ -n "${off}" ]; then
		trigger='timer'
		brightness='255'
	else
		trigger='none'
		brightness="${on}"
	fi
	
	echo "${trigger}" > "${ledpath}/trigger"
	echo "${brightness}" > "${ledpath}/brightness"
	
	if [ -n "${off}" ]; then
		echo "${on}" > "${ledpath}/delay_on"
		echo "${off}" > "${ledpath}/delay_off"
	fi
}

set_leds_tplink_mr3020()
{
	local state="${1}"
	
	case "${state}" in
		'start')
			set_led "${LEDS_KERNEL}" 0
			set_led "${LEDS_NETWORK}" 0
			set_led "${LEDS_FIRMWARE}" 1000 1000
			set_led "${LEDS_SPARE}" 1
			;;
		
		'reg-init')
			set_led "${LEDS_FIRMWARE}" 250 1000
			;;
		
		'ctrl-init')
			set_led "${LEDS_FIRMWARE}" 500 250
			;;
		
		'keep-start')
			set_led "${LEDS_FIRMWARE}" 1000 250
			;;
		
		'keep-found')
			set_led "${LEDS_FIRMWARE}" 1
			;;
		
		'net-try')
			set_led "${LEDS_NETWORK}" 1000 1000
			;;
		
		'net-ok')
			set_led "${LEDS_NETWORK}" 1
			;;
		
		'net-fail')
			set_led "${LEDS_NETWORK}" 250 250
			;;
		
		*)
			;;
esac
}
