#!/usr/bin/env sh
# Start an ephemeral Postgres for `make test-postgres`.
#
# CI is expected to provide VESTA_TEST_POSTGRES from a service container instead; this is
# for local runs, so that "the suite passes on my machine" means both backends rather than
# only the convenient one.
set -eu

PGBIN="${PGBIN:-$(ls -d /opt/homebrew/opt/postgresql@*/bin 2>/dev/null | head -1)}"
[ -n "$PGBIN" ] || { echo "postgres not found; set PGBIN"; exit 1; }
export PATH="$PGBIN:$PATH"

DATA="${DATA:-${TMPDIR:-/tmp}/vesta-pgdata}"
# Deliberately short: a unix socket path over ~103 bytes fails to bind, and a long TMPDIR
# produces a confusing "could not create any Unix-domain sockets" rather than a clear one.
SOCK="${SOCK:-/tmp/vpg}"
PORT="${PORT:-55432}"

case "${1:-start}" in
start)
	[ -d "$DATA" ] || initdb -D "$DATA" -U vesta --auth=trust -E UTF8 >/dev/null
	mkdir -p "$SOCK"
	pg_ctl -D "$DATA" -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" \
	       -l "$DATA/log" start >/dev/null 2>&1 || true
	sleep 2
	createdb -h 127.0.0.1 -p "$PORT" -U vesta vesta_test 2>/dev/null || true
	echo "postgres://vesta@127.0.0.1:$PORT/vesta_test?sslmode=disable"
	;;
stop)
	pg_ctl -D "$DATA" stop >/dev/null 2>&1 || true
	;;
*)
	echo "usage: $0 [start|stop]" >&2
	exit 2
	;;
esac
