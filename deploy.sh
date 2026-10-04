#!/usr/bin/env bash
#
# Rebuild this plugin on the CPA host and install it, without a local Go
# toolchain: the source is uploaded, compiled inside the golang container on the
# target, and the resulting library is dropped straight into CPA's plugin
# directory. Unit tests run as part of the build and a failure aborts the deploy.
#
# Usage:
#   cp .env.example .env && $EDITOR .env      # once, per machine
#   ./deploy.sh
#
# or inline:
#   NAS_HOST=192.0.2.10 NAS_PASS='...' CPA_DIR=/path/to/cpa ./deploy.sh
#
# Environment (a local .env is sourced first; it is gitignored):
#   NAS_HOST       required  host that runs the CPA container
#   NAS_PASS       required  ssh password for that host
#   CPA_DIR        required  CPA's config directory on that host
#   CPA_MGMT_KEY   optional  CPA management key; when set the plugin is reloaded
#                            and the deployed version is verified
#   SSH_PORT       optional  default 22
#   SSH_USER       optional  default root
#   CPA_PORT       optional  default 8317
#   DOCKER         optional  default docker (absolute path if not on PATH)
#
# Nothing secret is stored in this repo: the password and the management key live
# in the environment or in the gitignored .env.

set -euo pipefail

cd "$(dirname "$0")"
[ -f .env ] && . ./.env

NAS_HOST="${NAS_HOST:?set NAS_HOST (see .env.example)}"
NAS_PASS="${NAS_PASS:?set NAS_PASS (see .env.example)}"
CPA_DIR="${CPA_DIR:?set CPA_DIR (see .env.example)}"
CPA_MGMT_KEY="${CPA_MGMT_KEY:-}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-root}"
CPA_PORT="${CPA_PORT:-8317}"
DOCKER="${DOCKER:-docker}"

PLUGIN_ID="$(grep -E 'pluginID[[:space:]]+=' main.go | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
VERSION="$(grep -E 'pluginVersion[[:space:]]+=' main.go | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$PLUGIN_ID" ] && [ -n "$VERSION" ] || { echo "cannot read pluginID/pluginVersion from main.go" >&2; exit 1; }

LIB="${PLUGIN_ID}-v${VERSION}.so"
STAGE="/tmp/${PLUGIN_ID}-deploy-$$"
trap 'rm -rf "$STAGE" /tmp/${PLUGIN_ID}-src.tgz; [ -n "${RESULT:-}" ] && rm -f "$RESULT"' EXIT

echo "plugin : $PLUGIN_ID v$VERSION"
echo "target : ${SSH_USER}@${NAS_HOST}:${SSH_PORT}"
echo "install: ${CPA_DIR}/plugins/linux/amd64/${LIB}"

# --- ssh wrapper ------------------------------------------------------------
# Non-interactive ssh cannot answer a password prompt, and sshpass is not
# available on macOS. expect is.
command -v expect >/dev/null || { echo "expect is required" >&2; exit 1; }
cat > "$STAGE.exp" <<'EXP'
#!/usr/bin/expect -f
set timeout 900
set pass [lindex $argv 0]
set cmd  [lindex $argv 1]
# keep the spawn banner and the password prompt out of the deploy log
log_user 0
spawn ssh -p $env(SSH_PORT) -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 $env(SSH_USER)@$env(NAS_HOST) $cmd
expect "*assword:"
send "$pass\r"
log_user 1
expect eof
EXP
chmod +x "$STAGE.exp"
ssh_do() { SSH_PORT="$SSH_PORT" SSH_USER="$SSH_USER" NAS_HOST="$NAS_HOST" "$STAGE.exp" "$NAS_PASS" "$1"; }
trap 'rm -rf "$STAGE" "$STAGE.exp" /tmp/${PLUGIN_ID}-src.tgz' EXIT

# --- 1. upload the source ---------------------------------------------------
REMOTE_SRC="/tmp/${PLUGIN_ID}-src"
tar czf /tmp/${PLUGIN_ID}-src.tgz --exclude .git --exclude dist --exclude '*.so' .
B64="$(base64 < /tmp/${PLUGIN_ID}-src.tgz | tr -d '\n')"
echo "[1/5] uploading $(wc -c < /tmp/${PLUGIN_ID}-src.tgz | tr -d ' ') bytes"
ssh_do "rm -rf '$REMOTE_SRC' && mkdir -p '$REMOTE_SRC' && echo '$B64' | base64 -d > '$REMOTE_SRC.tgz' && tar xzf '$REMOTE_SRC.tgz' -C '$REMOTE_SRC' && echo staged" >/dev/null

# --- 2. build (tests run inside) --------------------------------------------
echo "[2/5] building on target (unit tests run as part of the build)"
BUILD_LOG="$(ssh_do "cd '$REMOTE_SRC' && $DOCKER build -f Dockerfile.build -t ${PLUGIN_ID}-deploy . 2>&1 | tail -4")"
echo "$BUILD_LOG" | sed 's/^/      /'
echo "$BUILD_LOG" | grep -qE 'Successfully tagged|naming to' || { echo "build failed" >&2; exit 1; }

# --- 3. install -------------------------------------------------------------
echo "[3/5] installing ${LIB}"
ssh_do "set -e; cd '$REMOTE_SRC'; ID=\$($DOCKER create ${PLUGIN_ID}-deploy); $DOCKER cp \$ID:/out/${PLUGIN_ID}.so './${LIB}'; $DOCKER rm \$ID >/dev/null; \
        install -m 644 './${LIB}' '${CPA_DIR}/plugins/linux/amd64/${LIB}'; \
        ls '${CPA_DIR}/plugins/linux/amd64/' | grep -E '^${PLUGIN_ID}-v' | grep -v \"^${LIB}\$\" | while read -r old; do rm -f '${CPA_DIR}/plugins/linux/amd64/'\$old; echo \"  removed \$old\"; done; \
        $DOCKER rmi ${PLUGIN_ID}-deploy >/dev/null 2>&1 || true; \
        echo installed" | tail -5

# --- 4. reload --------------------------------------------------------------
if [ -n "$CPA_MGMT_KEY" ]; then
  echo "[4/5] reloading the plugin"
  for state in false true; do
    curl -s --max-time 30 -o /dev/null -w "      enabled=${state} -> %{http_code}\n" \
      -X PATCH "http://${NAS_HOST}:${CPA_PORT}/v0/management/plugins/${PLUGIN_ID}/enabled" \
      -H "Authorization: Bearer ${CPA_MGMT_KEY}" -H 'Content-Type: application/json' \
      -d "{\"enabled\":${state}}"
    sleep 3
  done
else
  echo "[4/5] skipped reload (set CPA_MGMT_KEY to do it automatically)"
fi

# --- 5. verify --------------------------------------------------------------
if [ -n "$CPA_MGMT_KEY" ]; then
  echo "[5/5] verifying"
  curl -s --max-time 20 "http://${NAS_HOST}:${CPA_PORT}/v0/management/plugins" \
    -H "Authorization: Bearer ${CPA_MGMT_KEY}" | python3 -c "
import json,sys
for p in json.load(sys.stdin)['plugins']:
    if p['id'] == '${PLUGIN_ID}':
        print('      version  :', p['metadata']['version'])
        print('      file     :', p['path'].split('/')[-1])
        print('      enabled  :', p['effective_enabled'])
        print('      console  : /v0/resource/plugins/${PLUGIN_ID}/console')
        break
else:
    print('      plugin not listed')
"
else
  echo "[5/5] skipped verification"
fi

echo "done."
