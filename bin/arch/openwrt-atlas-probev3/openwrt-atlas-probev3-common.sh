# Files
LEDS_KERNEL=/tmp/leds/kernel
LEDS_FIRMWARE=/tmp/leds/firmware
LEDS_NETWORK=/tmp/leds/network
LEDS_SPARE=/tmp/leds/spare

# Commands
SET_LEDS_CMD=set_leds
BUDDYINFO=do_buddyinfo

# Config
IPV6_INF="br-lan"

set_leds()
{
	state="$1"
	case X"$state" in
	Xstart)
		echo 0 40 > $LEDS_KERNEL
		echo 4 4 > $LEDS_FIRMWARE
		echo 0 0 > $LEDS_NETWORK
		echo 0 0 > $LEDS_SPARE
	;;
	Xreg-init)
		echo 1 4 > $LEDS_FIRMWARE
	;;
	Xctrl-init)
		echo 2 1 > $LEDS_FIRMWARE
	;;
	Xkeep-start)
		echo 4 1 > $LEDS_FIRMWARE
	;;
	Xkeep-found)
		echo 40 0 > $LEDS_FIRMWARE
	;;
	Xnet-try)
		echo 4 4 > $LEDS_NETWORK
	;;
	Xnet-ok)
		echo 40 0 > $LEDS_NETWORK
	;;
	Xnet-fail)
		echo 1 1 > $LEDS_NETWORK
	;;
	esac
}
