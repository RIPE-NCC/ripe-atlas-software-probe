#!/bin/sh
# Support routines
# Copyright (c) 2022 RIPE NCC
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
# 

#                                                                                           
# function to get the running version of the firmware
# Usage: fw_version <type>
# <type> must be 'application' or 'kernel' to indicate
# the version sought
#
fw_version()
{
	local type="${1}"
	local file=''
	local res

	case "${type}" in
		'kernel')
			file="/mnt/oldroot/${STATE_DIR}/FIRMWARE_KERNEL_VERSION"
			if [ ! -f "${file}" ]; then
				file="${STATE_DIR}/FIRMWARE_KERNEL_VERSION"
			fi
			;;

		'application'|'app')
			file="${STATE_DIR}/FIRMWARE_APPS_VERSION"
			;;

		*)
			res=1
			;;
	esac

	if [ -n "${file}" ]; then
		cat "${file}" 2>/dev/null
		res=${?}
	fi
		
	return ${res}
}
