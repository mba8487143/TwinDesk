#!/usr/bin/env bash
# TwinDesk Relay on Ubuntu (22.04, 24.04 or later): install, or update when it's already there.
#   sudo bash install.sh                 # from a TwinDesk checkout (uses ../twindesk-relay.js)
#   curl -fsSL https://raw.githubusercontent.com/<owner>/TwinDesk/<ref>/relay/deploy/install.sh | sudo REPO=<owner>/TwinDesk REF=<ref> bash
# Environment: PORT (default 47100, first install only), REPO (default InukaAsith/TwinDesk),
# REF (default main), OPEN_UFW (default 1: allow the port in ufw when ufw is on).
# Run it again to update: the key and port in /etc/twindesk-relay.env stay as they are.
# GPL-3.0, see LICENSE. docs/relay.md has the same steps by hand.
set -euo pipefail

PORT="${PORT:-47100}"
REPO="${REPO:-InukaAsith/TwinDesk}"
REF="${REF:-main}"
OPEN_UFW="${OPEN_UFW:-1}"
USER_NAME=twindesk-relay
DIR=/opt/twindesk-relay
ENV_FILE=/etc/twindesk-relay.env
UNIT=/etc/systemd/system/twindesk-relay.service
NODE_MIN=18

say() { printf '\n== %s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it as root (sudo bash install.sh)"
command -v systemctl >/dev/null || die "this script needs systemd"
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "PORT must be 1 to 65535"
[[ "$REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || die "REPO must look like owner/TwinDesk"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "REF must be a branch, tag or commit"

# A checkout's own files only when this script is a file there (not piped from curl: then the
# current directory says nothing, and both files come from REPO@REF).
HERE=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; fi
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl openssl >/dev/null

say "Node.js ($NODE_MIN or later)"
node_major() { node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || echo 0; }
if ! command -v node >/dev/null || [ "$(node_major)" -lt "$NODE_MIN" ]; then
  # Ubuntu 24.04's own nodejs is 18: enough. 22.04's is 12: too old, so Node 22 LTS from NodeSource.
  apt-get install -y -qq nodejs >/dev/null 2>&1 || true
  if ! command -v node >/dev/null || [ "$(node_major)" -lt "$NODE_MIN" ]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x -o "$TMP/nodesource.sh"
    bash "$TMP/nodesource.sh" >/dev/null
    apt-get install -y -qq nodejs >/dev/null
  fi
fi
[ "$(node_major)" -ge "$NODE_MIN" ] || die "Node.js $NODE_MIN or later didn't install (have: $(node -v 2>/dev/null || echo none))"
echo "node $(node -v)"

say "The relay"
if [ -n "$HERE" ] && [ -f "$HERE/../twindesk-relay.js" ]; then
  cp "$HERE/../twindesk-relay.js" "$TMP/twindesk-relay.js"
  echo "from this checkout"
else
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/relay/twindesk-relay.js" -o "$TMP/twindesk-relay.js"
  echo "from $REPO@$REF"
fi
head -c 40 "$TMP/twindesk-relay.js" | grep -q '^#!/usr/bin/env node' || die "that isn't the relay (check REPO and REF)"
node --check "$TMP/twindesk-relay.js" || die "the relay file doesn't parse"
id "$USER_NAME" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$USER_NAME"
install -d -m 0755 -o root -g root "$DIR"
install -m 0644 -o root -g root "$TMP/twindesk-relay.js" "$DIR/twindesk-relay.js"
sha256sum "$DIR/twindesk-relay.js"

say "Key and port"
if [ -f "$ENV_FILE" ]; then
  echo "kept $ENV_FILE (key and port as they were)"
else
  KEY="$(openssl rand -hex 24)"
  umask 077
  printf 'RELAY_PORT=%s\nRELAY_KEY=%s\nRELAY_HOST=0.0.0.0\n' "$PORT" "$KEY" > "$ENV_FILE"
  chown root:root "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
  echo "made $ENV_FILE"
fi
PORT_NOW="$(sed -n 's/^RELAY_PORT=//p' "$ENV_FILE" | tail -n1)"
KEY_NOW="$(sed -n 's/^RELAY_KEY=//p' "$ENV_FILE" | tail -n1)"

say "Service"
if [ -n "$HERE" ] && [ -f "$HERE/twindesk-relay.service" ]; then
  install -m 0644 "$HERE/twindesk-relay.service" "$UNIT"
else
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$REF/relay/deploy/twindesk-relay.service" -o "$TMP/unit"
  grep -q '^ExecStart=' "$TMP/unit" || die "that isn't the service file"
  install -m 0644 "$TMP/unit" "$UNIT"
fi
systemctl daemon-reload
systemctl enable twindesk-relay >/dev/null 2>&1
systemctl restart twindesk-relay
sleep 2
systemctl is-active --quiet twindesk-relay || { journalctl -u twindesk-relay -n 20 --no-pager; die "the service didn't start"; }
journalctl -u twindesk-relay -n 3 --no-pager -o cat | tail -n 3

say "Firewall"
if [ "$OPEN_UFW" = "1" ] && command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  ufw allow "${PORT_NOW}/tcp" comment 'TwinDesk Relay' >/dev/null
  echo "ufw: allowed ${PORT_NOW}/tcp"
else
  echo "ufw isn't on here. Allow TCP ${PORT_NOW} in your provider's firewall (security group) too."
fi

say "Check"
if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${PORT_NOW}" 2>/dev/null; then echo "listening on ${PORT_NOW}"; else die "nothing answers on ${PORT_NOW}"; fi

IPS="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -n 3 | tr '\n' ' ')"
cat <<DONE

TwinDesk Relay is running.
  In TwinDesk on each computer, General › Your own relay:
    Address: <this server's public IP or name>:${PORT_NOW}   (addresses here: ${IPS:-unknown})
    Key:     ${KEY_NOW}
  Keep the key private; it's in ${ENV_FILE} (root only).
  Logs: journalctl -u twindesk-relay -f      Update: run this script again.
DONE
