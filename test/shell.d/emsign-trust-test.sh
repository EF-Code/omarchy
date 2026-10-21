#!/bin/bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/base-test.sh"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT
mkdir -p "$test_dir/tree/install/config" "$test_dir/bin"
leaf="$test_dir/tree/install/config/block-emsign-root.sh"
blocklist="$test_dir/trust/blocklist/omarchy-emsign-ecc-root-ca-g3.pem"
sed "s|/etc/ca-certificates/trust-source|$test_dir/trust|g" \
  "$ROOT/install/config/block-emsign-root.sh" >"$leaf"
cp "$ROOT/install/config/emsign-ecc-root-ca-g3.pem" "${leaf%/*}/"
export OMARCHY_PATH="$test_dir/tree" CALL_LOG="$test_dir/calls"
export PATH="$test_dir/bin:$PATH"

cat >"$test_dir/bin/update-ca-trust" <<'STUB'
#!/bin/bash
echo extract >>"$CALL_LOG"
exit "${EXTRACT_STATUS:-0}"
STUB
cat >"$test_dir/bin/sudo" <<'STUB'
#!/bin/bash
[[ ${SUDO_ALLOWED:-1} == "1" ]] || exit 1
exec "$@"
STUB
chmod +x "$test_dir/bin/"*

bash -euo pipefail "$leaf"
cmp -s "$ROOT/install/config/emsign-ecc-root-ca-g3.pem" "$blocklist" || fail "installed root matches the reviewed certificate"
[[ $(stat -c %a "$blocklist") == "644" ]] || fail "blocklist is world-readable"
pass "new installation installs the exact root and regenerates trust"

bash -euo pipefail "$leaf"
[[ $(wc -l <"$CALL_LOG") == "2" ]] || fail "rerun regenerates trust"
pass "rerun preserves the blocklist and retries trust extraction"

if EXTRACT_STATUS=7 bash -euo pipefail "$ROOT/migrations/1792551241.sh"; then
  fail "failed trust extraction must fail the migration"
fi
bash -euo pipefail "$ROOT/migrations/1792551241.sh"
pass "migration propagates extraction failure and succeeds on retry"

if SUDO_ALLOWED=0 bash -euo pipefail "$ROOT/migrations/1792551241.sh"; then
  fail "refused sudo must fail the migration"
fi
pass "migration stays retryable when privilege is refused"

printf 'administrator policy\n' >"$blocklist"
before=$(wc -l <"$CALL_LOG")
if bash -euo pipefail "$leaf"; then
  fail "modified blocklist must not be overwritten"
fi
[[ $(cat "$blocklist") == "administrator policy" ]] || fail "administrator file is preserved"
[[ $(wc -l <"$CALL_LOG") == "$before" ]] || fail "conflict must not report a successful extraction"
pass "unknown blocklist contents are preserved and reported"

rm "$blocklist"
printf 'symlink target\n' >"$test_dir/admin.pem"
ln -s "$test_dir/admin.pem" "$blocklist"
if bash -euo pipefail "$leaf"; then
  fail "symlink blocklist must be rejected"
fi
[[ -L $blocklist && $(cat "$test_dir/admin.pem") == "symlink target" ]] || fail "symlink target is preserved"
pass "blocklist symlinks are rejected without touching their targets"

fingerprint=$(openssl x509 -in "$ROOT/install/config/emsign-ecc-root-ca-g3.pem" -noout -fingerprint -sha256)
[[ ${fingerprint//:/} == "sha256 Fingerprint=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B" ]] || fail "vendored root has the advisory fingerprint"
grep -qFx 'run_logged "$OMARCHY_INSTALL/config/block-emsign-root.sh"' "$ROOT/install/config/all.sh" || fail "system setup runs the trust remedy"
pass "reviewed certificate and fresh-install integration are retained"
