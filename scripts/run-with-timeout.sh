#!/bin/sh

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <seconds> <command> [args...]" >&2
    exit 2
fi

seconds=$1
shift

"$@" &
cmd_pid=$!

(
    sleep "$seconds"
    kill -TERM "$cmd_pid" 2> /dev/null || exit 0
    sleep 1
    kill -KILL "$cmd_pid" 2> /dev/null || exit 0
) &
timer_pid=$!

cleanup()
{
    kill "$timer_pid" 2> /dev/null || true
}

trap cleanup EXIT INT TERM HUP

# Capture wait's own status. Reading $? after an `if wait ...; then ... fi`
# yields the status of the *if* compound (0 when the condition fails and there
# is no else branch), which silently turned every failure into success.
status=0
wait "$cmd_pid" || status=$?

cleanup
wait "$timer_pid" 2> /dev/null || true

if [ "$status" -eq 143 ] || [ "$status" -eq 137 ]; then
    exit 124
fi
exit "$status"
