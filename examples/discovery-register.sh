#!/bin/sh
# discovery-register.sh — self-register a backend into a limer `discover` pool
# and heartbeat it, then deregister on exit. Run it beside your service.
#
#   LIMER_ADMIN_SECRET=... ./discovery-register.sh http://10.0.0.1:2019 orders 8080
#
# This is the "your own service is the plugin" approach: limer stays out of
# Docker/Kubernetes/Consul; a small program like this one pushes membership to
# the admin API. Rewrite it in any language, or drive /register straight from
# your orchestrator's events.
set -eu

ADMIN=${1:?usage: discovery-register.sh <admin-url> <service> <port> [ttl]}
SERVICE=${2:?service name}
PORT=${3:?port this backend serves on}
TTL=${4:-15}
: "${LIMER_ADMIN_SECRET:?set LIMER_ADMIN_SECRET}"
AUTH="Authorization: Bearer $LIMER_ADMIN_SECRET"

deregister() {
    curl -fsS -X POST -H "$AUTH" \
        "$ADMIN/deregister?service=$SERVICE&port=$PORT" >/dev/null 2>&1 || true
    exit 0
}
trap deregister INT TERM EXIT

# Heartbeat at a third of the TTL so a missed beat or two does not evict us.
INTERVAL=$(( TTL / 3 )); [ "$INTERVAL" -lt 1 ] && INTERVAL=1
while :; do
    if ! curl -fsS -X POST -H "$AUTH" \
        "$ADMIN/register?service=$SERVICE&port=$PORT&ttl=$TTL" >/dev/null; then
        echo "discovery-register: register failed, retrying" >&2
    fi
    sleep "$INTERVAL"
done
