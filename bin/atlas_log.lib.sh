#!/bin/sh
#
# RIPE Atlas logging in shell script
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

# Global variables
_atlas_log_kernel_version=$(fw_version 'kernel')
_atlas_log_application_version=$(fw_version 'application')

#
# Internal function with JSON objects added for process restart
# Usage: _atlas_log_process_died <encoder> <process name> <message>
#
_atlas_log_process_died()
{
	local encoder="${1}"
	local process="${2}"
	local message="${3}"

	if [ ${#} -lt 3 ]; then
		return 1
	fi

	${encoder} set 'fw' integer "${_atlas_log_application_version}"
	${encoder} set 'process' string "${process}"
	${encoder} set 'message' string "${message}"

	return 0
}

#
# Internal function with JSON objects added for simple log messages
# Usage: _atlas_log_basic <encoder> <message>
#
_atlas_log_basic()
{
	local encoder="${1}"
	local message="${2}"

	if [ ${#} -lt 2 ]; then
		return 1
	fi

	${encoder} set ether_addr string "${ETHER_SCANNED}"
	${encoder} set state string 'done'
	${encoder} set 'message' string "${message}"

	return 0
}

#
# Internal function with JSON objects added for failed measurement commands
# Usage: _atlas_log_failed_command <encoder> <command>
#
_atlas_log_failed_command()
{
	local encoder="${1}"
	local cmd="${2}"

	if [ ${#} -lt 2 ]; then
		return 1
	fi

	${encoder} set 'fw' integer "${_atlas_log_application_version}"
	${encoder} set 'cmd' string "${cmd//\"/\\\"}"

	return 0
}

#
# Internal function to indicate a non-existing message <id>
# Usage: _atlas_log_unknown_handler
# Output is the handler found, or an error handler otherwise
#
_atlas_log_unknown_handler()
{
	return 1
}

#
# Internal function to match message ids to handler functions
# Usage: _atlas_log_lookup_handler <id>
# Output is the handler found, or an error handler otherwise
#
_atlas_log_lookup_handler()
{
	local id="${1}"
	local handler

	case "${id}" in
		'9000')
			handler=_atlas_log_basic
			;;

		'9801'|'9802'|'9803'|'9804'|'9805'|'9806'|'9807'|'9808'|'9809')
			handler=_atlas_log_failed_command
			;;

		'9811'|'9812'|'9813'|'9814'|'9815'|'9816'|'9817'|'9818'|'9819')
			handler=_atlas_log_process_died
			;;

		*)
			handler=_atlas_log_unknown_handler
			;;
	esac

	echo "${handler}"
}

#
# Function to compose JSON formatted log messages
# Usage: atlas_log_compose <id> <handler> [<args>]
# Any args are passed directly to the <handler> function
# Output is written to the simpleping file
#
atlas_log_compose()
{
	local id
	local handler
	local encoder
	local output
	local res

	id="${1}"
	shift
	handler="${1}"
	shift

	new json encoder

	${encoder} set 'id' string "${id}"
	${encoder} set 'time' integer $(epoch)

	${handler} ${encoder} "${@}"
	res=${?}

	if [ ${res} -eq 0 ]; then
		output="$(${encoder} encode)"
		res=${?}
	fi

	delete encoder

	if [ ${res} -eq 0 ]; then
		echo "RESULT ${output}" >> ${DATA_NEW_DIR}/simpleping
	fi

	return ${res}
}

#
# Function to log JSON formatted messages
# Usage: atlas_log <encoder> <handler> [<args>]
# Any args are passed directly to the <handler> function
# Output is written to the simpleping file
#
atlas_log()
{
	local id
	local handler

	id="${1}"
	shift

	handler=$(_atlas_log_lookup_handler "${id}")

	atlas_log_compose "${id}" ${handler} "${@}"
	return ${?}
}
