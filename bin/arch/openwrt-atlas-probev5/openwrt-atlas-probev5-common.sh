# Files
# Commands

SET_LEDS_CMD=set_leds_nanopi_neo_plus2
BUDDYINFO=do_buddyinfo
MOUNT_ROOT_RO=mount_root_ro

# Config
IPV6_INF="br-lan"

mount_root_ro()
{
	mount -o remount,ro /
	mount -o remount,rw /storage
}
set_leds_nanopi_neo_plus2()
{
	state="$1"
	case X"$state" in

	Xkeep-found)
		echo timer > /sys/class/leds/nanopi\:green\:pwr/trigger
	;;
	esac
}
