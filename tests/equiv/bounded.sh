#!/bin/bash
# Run one unittest selection of the equivalence harness with a wall-clock
# bound, in a session of its own.
#
#     tests/equiv/bounded.sh SECONDS test_equiv.Class [test_equiv.Class ...]
#
# `timeout` signals only its child, and the gate's drivers fork runs of their
# own, so when the harness stalled the step outlived its timeout by the life of
# the orphans holding its output open. Here the selection runs as a session
# leader writing to a file, not to the step's pipe, so nothing left behind can
# keep the step alive; the file is printed when the selection ends. Past the
# bound the process tree is printed (what is stuck, and in which kernel wait),
# Python is sent SIGABRT so PYTHONFAULTHANDLER prints every thread's stack, and
# the whole session is killed.
set -u
limit=$1
shift
cd "$(dirname "$0")"
log=$(mktemp "${TMPDIR:-/tmp}/equiv-bounded.XXXXXX")
setsid python3 -m unittest -v "$@" >"$log" 2>&1 </dev/null &
pid=$!
for ((i = 0; i < limit; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid"
        status=$?
        cat "$log"
        exit "$status"
    fi
    sleep 1
done
echo "::error::$* ran past ${limit}s; the processes still running:"
ps -eo pid,ppid,pgid,sid,stat,etime,wchan:24,args --forest | grep -v ' \[' | tail -n 80
kill -ABRT "$pid" 2>/dev/null
sleep 5
kill -KILL -- "-$pid" 2>/dev/null
cat "$log"
exit 124
