#!/usr/bin/env bash
#
# Non-interactive adversarial test for the Midnight agent path. Every scenario is something a
# misbehaving agent, a hostile dapp or a careless user can do, and each one asserts the whole
# outcome rather than an exit code: the request is refused, the refusal names the reason, no
# signature or transaction comes back, the audit log records the verdict, and no secret (token,
# owner passphrase, mnemonic) reaches the output or the log.
#
# OFFLINE tier (always runs): needs no indexer, node, prover or funds, so it runs anywhere. It works
# in a throwaway vault under a temp HOME and never reads or writes ~/.ows. It covers token scope,
# revocation and expiry, both policy passes (the request-shape pass and the effect pass at the
# plan→authorize seam, which a makeIntent that spends no coin reaches without a network because its
# effects come from the request), executable policies that crash, hang, print garbage or are missing
# (each must deny), malformed and hostile connector requests (misspelled options, unnamed tokens, a
# plaintext remote indexer), the audit record of a token's balance read, outages (an indexer or proof
# server that is down, a node or proof server on another host over plaintext), a submitTransaction
# relay of a transaction the node would refuse, and secret hygiene.
#
# LIVE tier (LIVE=1): the plan-derived flows. They sync a FUNDED wallet against a live indexer and
# mock-prove, so they use your real vault — set WALLET (and PASS, its owner passphrase, empty by
# default). Every live scenario is refused before anything is proved or broadcast; the script mints
# its own policy and token and revokes them on exit.
#
# Usage:  ./midnight-adversarial.sh                       # offline tier, midnight:preview
#         LIVE=1 WALLET=<name> [PASS=…] ./midnight-adversarial.sh midnight:preprod
# Env:    PROFILE=release (default debug: nothing here is crypto-heavy offline)
#         OWS=<path to an ows binary> skips the build
#
# Exit status: 0 when every scenario held, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$SCRIPT_DIR/../ows"
CHAIN="${1:-${CHAIN:-midnight:preview}}"
LIVE="${LIVE:-}"
PROFILE="${PROFILE:-debug}"

if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RESET=$'\e[0m'; GREEN=$'\e[32m'; RED=$'\e[31m'; BLUE=$'\e[34m'
else
  BOLD=; DIM=; RESET=; GREEN=; RED=; BLUE=
fi
say()  { printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$1" "$RESET"; }

PASSED=0; FAILED=0; FAILURES=()
pass() { printf '%s✓ %s%s\n' "$GREEN" "$1" "$RESET"; PASSED=$((PASSED + 1)); }
fail() { printf '%s✗ %s%s\n' "$RED" "$1" "$RESET"; FAILED=$((FAILED + 1)); FAILURES+=("$1"); }

# ── Build ───────────────────────────────────────────────────────────────────────────────────
if [ -z "${OWS:-}" ]; then
  if [ "$PROFILE" = release ]; then
    cargo build --release -p ows-cli --manifest-path "$WORKSPACE/Cargo.toml" || exit 1
    OWS="$WORKSPACE/target/release/ows"
  else
    cargo build -p ows-cli --manifest-path "$WORKSPACE/Cargo.toml" || exit 1
    OWS="$WORKSPACE/target/debug/ows"
  fi
fi
[ -x "$OWS" ] || { fail "no ows binary at $OWS"; exit 1; }
command -v python3 >/dev/null || { fail "python3 is needed for the executable policies"; exit 1; }

say "ows Midnight adversarial test — $CHAIN"
note "binary: $OWS"

# ── Sandbox ─────────────────────────────────────────────────────────────────────────────────
SANDBOX="$(mktemp -d)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT
AUDIT_LOG="$SANDBOX/.ows/logs/audit.jsonl"

# The well-known BIP-39 test vector: its words are searched for in every output below.
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
OWNER_PASS=""
SECRETS=("$MNEMONIC" "$OWNER_PASS")

# Run ows in the sandbox with a credential. Sets OUT (stdout+stderr) and RC.
#   sandboxed <token|pass|unset> <credential> <ows args…>
sandboxed() {
  local mode="$1" cred="$2"; shift 2
  if [ "$mode" = unset ]; then
    OUT="$(env -u OWS_PASSPHRASE -u LWS_PASSPHRASE HOME="$SANDBOX" "$OWS" "$@" </dev/null 2>&1)"
  else
    OUT="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_PASSPHRASE="$cred" "$OWS" "$@" </dev/null 2>&1)"
  fi
  RC=$?
}

# No secret may appear in $1 (a captured output) or in the audit log.
no_secrets() {
  local label="$1" text="$2" s
  for s in "${SECRETS[@]}"; do
    [ -n "$s" ] || continue
    if printf '%s' "$text" | grep -qF -- "$s"; then fail "$label: a secret appeared in the output"; return 1; fi
    if [ -f "$AUDIT_LOG" ] && grep -qF -- "$s" "$AUDIT_LOG"; then fail "$label: a secret appeared in the audit log"; return 1; fi
  done
  return 0
}

# The last sandboxed call must have been refused, naming $2, with nothing signed and nothing leaked.
refused() {
  local label="$1" needle="$2"
  if [ "$RC" -eq 0 ]; then fail "$label: accepted — expected a refusal mentioning '$needle'"; return; fi
  if [ "$RC" -eq 101 ]; then fail "$label: panicked instead of refusing"; return; fi
  if ! printf '%s' "$OUT" | grep -qiF -- "$needle"; then
    fail "$label: refused, but not for '$needle': $(printf '%s' "$OUT" | grep -v '^warning:' | head -3 | tr '\n' ' ')"; return
  fi
  if printf '%s' "$OUT" | grep -qE '"(signature|transaction)"'; then fail "$label: a signature came back with the refusal"; return; fi
  no_secrets "$label" "$OUT" || return
  pass "$label"
}

# The newest audit record must be operation $2 and carry $3 in its details.
audited() {
  local label="$1" op="$2" needle="$3" last
  last="$(tail -n 1 "$AUDIT_LOG" 2>/dev/null)"
  if printf '%s' "$last" | grep -qF "\"operation\":\"$op\"" && printf '%s' "$last" | grep -qF -- "$needle"; then
    pass "$label"
  else
    fail "$label: newest audit record is: ${last:-<none>}"
  fi
}

# ── Vault: two wallets, policies, tokens ───────────────────────────────────────────────────
say "Setting up a throwaway vault"
OUT="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_MNEMONIC="$MNEMONIC" OWS_PASSPHRASE="$OWNER_PASS" \
  "$OWS" wallet import --name guarded --mnemonic </dev/null 2>&1)" || { fail "import the guarded wallet: $OUT"; exit 1; }
OUT="$(env -u OWS_PASSPHRASE -u LWS_PASSPHRASE HOME="$SANDBOX" "$OWS" wallet create --name open </dev/null 2>&1)" \
  || { fail "create the open wallet: $OUT"; exit 1; }

POLICIES="$SANDBOX/policies"; mkdir -p "$POLICIES"
policy() {  # policy <id> <rules-json> <executable-or-empty>
  local id="$1" rules="$2" exe="$3" exe_json=null
  [ -n "$exe" ] && exe_json="\"$exe\""
  printf '{"id":"%s","name":"%s","version":1,"created_at":"2026-10-28T00:00:00Z","rules":%s,"executable":%s,"action":"deny"}\n' \
    "$id" "$id" "$rules" "$exe_json" > "$POLICIES/$id.json"
  HOME="$SANDBOX" "$OWS" policy create --file "$POLICIES/$id.json" >/dev/null 2>&1 || { fail "register policy $id"; exit 1; }
}
program() {  # program <name> <python body>; prints the path
  local p="$POLICIES/$1.py"
  printf '#!/usr/bin/env python3\nimport sys, json\n%s\n' "$2" > "$p"; chmod 755 "$p"; printf '%s' "$p"
}

ONLY_CHAIN="[{\"type\":\"allowed_chains\",\"chain_ids\":[\"$CHAIN\"]}]"
# Cap the summed absolute wallet-relative movement the effect pass reports, at 1,000,000.
CAP_PY="$(program cap 'ctx = json.load(sys.stdin)
extra = (ctx.get("transaction") or {}).get("chain_extra") or {}
total = sum(abs(int(d)) for s in extra.get("segment_effects", []) for e in s.get("effects", []) for _, d in e.get("diff", []))
print(json.dumps({"allow": total <= 1_000_000, "reason": f"summed movement {total} (cap 1000000)"}))')"
policy cap "$ONLY_CHAIN" "$CAP_PY"
policy crash   "[]" "$(program crash 'sys.exit(3)')"
policy garbage "[]" "$(program garbage 'print("allow")')"
policy hang    "[]" "$(program hang 'import time; time.sleep(30)')"
policy missing "[]" "$POLICIES/does-not-exist.py"

mint() {  # mint <name> <wallet> <policy> [expires-at] — prints the token
  local extra=() out
  [ -n "${4:-}" ] && extra=(--expires-at "$4")
  out="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_PASSPHRASE="$OWNER_PASS" "$OWS" key create \
    --name "$1" --wallet "$2" --policy "$3" ${extra[@]+"${extra[@]}"} </dev/null 2>&1)"
  printf '%s' "$out" | grep -oE 'ows_key_[A-Za-z0-9_.-]+' | head -1
}
CAP_TOKEN="$(mint cap-agent guarded cap)"
CRASH_TOKEN="$(mint crash-agent guarded crash)"
GARBAGE_TOKEN="$(mint garbage-agent guarded garbage)"
HANG_TOKEN="$(mint hang-agent guarded hang)"
MISSING_TOKEN="$(mint missing-agent guarded missing)"
EXPIRED_TOKEN="$(mint expired-agent guarded cap 2001-01-01T00:00:00Z)"
REVOKED_TOKEN="$(mint revoked-agent guarded cap)"
for t in CAP CRASH GARBAGE HANG MISSING EXPIRED REVOKED; do
  v="${t}_TOKEN"; [ -n "${!v}" ] || { fail "mint the $t token"; exit 1; }
  SECRETS+=("${!v}")
done
REVOKED_ID="$(HOME="$SANDBOX" "$OWS" key list 2>/dev/null | awk '/^ID:/{id=$2} /^Name:/{ if ($2=="revoked-agent") print id }')"
HOME="$SANDBOX" "$OWS" key revoke --id "$REVOKED_ID" --confirm >/dev/null 2>&1 || { fail "revoke the revoked-agent key"; exit 1; }

# Request fixtures. makeIntent effects come from the request itself, and an offer that spends no coin
# plans without syncing the wallet, so its second policy pass runs with no network: an offer asking for
# 5,000,000 NIGHT back to the wallet is over the cap and refused there, before anything is built or
# proved. (An offer that spends coins syncs the wallet to pick them when it is planned.)
intent() {  # intent <value> [extra options JSON, starting with a comma]
  printf '{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"%s"}],"desiredOutputs":[],"options":{"intentId":1%s}}' "$1" "${2:-}"
}
GUARDED_ADDR="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_MNEMONIC="$MNEMONIC" "$OWS" mnemonic derive --chain "$CHAIN" </dev/null 2>/dev/null | tail -n 1)"
[ -n "$GUARDED_ADDR" ] || { fail "derive the guarded wallet's address"; exit 1; }
OVER_CAP="$(printf '{"method":"makeIntent","desiredInputs":[],"desiredOutputs":[{"kind":"unshielded","type":"night","value":"5000000","recipient":"%s"}],"options":{"intentId":1}}' "$GUARDED_ADDR")"

# ═══ Credentials: a token is the agent's only authority ═══════════════════════════════════
say "Credentials — a token must never degrade into owner authority"

sandboxed token "${CAP_TOKEN}x" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a mistyped token is refused" "API key"
sandboxed token "$CAP_TOKEN" sign tx --chain "$CHAIN" --wallet open --json --tx "$OVER_CAP"
refused "a token used on a wallet outside its scope is refused" "does not have access"
sandboxed token "$EXPIRED_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "an expired token is refused" "expired"
sandboxed token "$REVOKED_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a revoked token is refused" "API key"

# ═══ The two policy passes ════════════════════════════════════════════════════════════════
say "Policy passes — the request shape first, then the planned effects"

OTHER_CHAIN="midnight:preprod"; [ "$CHAIN" = "$OTHER_CHAIN" ] && OTHER_CHAIN="midnight:preview"
sandboxed token "$CAP_TOKEN" sign tx --chain "$OTHER_CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "first pass: a chain outside the policy's allowlist is refused" "not in allowlist"
audited "the first-pass denial is audited as an api_key denial" sign_transaction "actor=api_key, outcome=denied"
sandboxed token "$CAP_TOKEN" sign message --chain "$OTHER_CHAIN" --wallet guarded --message hi --json
refused "first pass: message signing is gated by the same allowlist" "not in allowlist"
sandboxed token "$CAP_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "second pass: a makeIntent over the movement cap is refused at the seam" "summed movement 5000000"
audited "the second-pass denial is audited with the policy's reason" sign_transaction "summed movement 5000000"
sandboxed token "$CAP_TOKEN" sign send-tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "second pass: send-tx is refused at the same seam, before any broadcast" "summed movement 5000000"

# ═══ Balance reads ════════════════════════════════════════════════════════════════════════
say "Balance reads — a token unseals the key to read balances, and the trail shows it"

sandboxed token "$CAP_TOKEN" fund balance --chain "$OTHER_CHAIN" --wallet guarded
refused "a balance read on a chain outside the token's allowlist is refused" "not in allowlist"
audited "the refused balance read is audited as an api_key denial" read_balance "actor=api_key, outcome=denied"
# A loopback indexer that refuses connections: the read is allowed and audited before the sync fails.
mkdir -p "$SANDBOX/.ows"
printf '{"vault_path":"%s","rpc":{"%s":"http://127.0.0.1:1/api/v4/graphql"}}\n' "$SANDBOX/.ows" "$CHAIN" \
  > "$SANDBOX/.ows/config.json"
sandboxed token "$CAP_TOKEN" fund balance --chain "$CHAIN" --wallet guarded
audited "an allowed balance read is audited as an api_key read" read_balance "actor=api_key, outcome=allowed"
rm -f "$SANDBOX/.ows/config.json"

# ═══ Executable policies fail closed ══════════════════════════════════════════════════════
say "Executable policies — any failure of the program is a denial"

sandboxed token "$CRASH_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a policy program that exits non-zero denies" "exited with"
sandboxed token "$GARBAGE_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a policy program that prints something other than a verdict denies" "invalid JSON"
sandboxed token "$MISSING_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a policy whose program is missing denies" "failed to start"
sandboxed token "$HANG_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$OVER_CAP"
refused "a policy program that hangs is killed and denies" "timed out"

# ═══ Hostile and malformed connector requests ═════════════════════════════════════════════
say "Requests — malformed or hostile input is refused cleanly, never a panic"

malformed() {  # malformed <label> <needle> <tx>
  sandboxed token "$CAP_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$3"
  refused "$1" "$2"
}
malformed "makeIntent payFees: true is refused" "payFees" "$(intent 5 ',"payFees":true')"
malformed "makeIntent into segment 0 is refused" "intentId must be >= 1" "$(printf '{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"night","value":"5"}],"desiredOutputs":[],"options":{"intentId":0}}')"
malformed "a makeIntent that has already expired is refused" "not in the future" "$(intent 5 ',"ttl":978307200')"
malformed "a makeIntent that outlives the ledger's global ttl is refused" "global_ttl" "$(intent 5 ',"ttl":99999999999')"
malformed "a negative amount is refused" "invalid" "$(intent -5)"
malformed "an amount past u128 is refused" "too large" "$(intent 999999999999999999999999999999999999999999)"
malformed "a request that is not JSON is refused" "DApp Connector request" "hello"
malformed "an unknown connector method is refused" "not yet implemented" '{"method":"drainWallet"}'
malformed "an empty request is refused" "invalid" '{}'
malformed "a transfer to an address on another network is refused" "network" "$(printf '{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"5","recipient":"mn_addr1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35qw3dyt6"}]}')"
malformed "a hex transaction that is not a Midnight transaction is refused" "invalid" "deadbeef"
malformed "a misspelled makeIntent option is refused, not ignored" "unknown field" "$(intent 5 ',"TTL":4102444800')"
malformed "a desired input with no token type is refused" "token type" "$(printf '{"method":"makeIntent","desiredInputs":[{"kind":"unshielded","type":"","value":"5"}],"desiredOutputs":[],"options":{"intentId":1}}')"

# A plaintext indexer on another host would carry the indexer's API key and the wallet's addresses in
# the clear; it is refused before anything connects.
mkdir -p "$SANDBOX/.ows"
printf '{"vault_path":"%s","rpc":{"%s":"http://indexer.example/api/v4/graphql?project_id=SECRETKEY"}}\n' \
  "$SANDBOX/.ows" "$CHAIN" > "$SANDBOX/.ows/config.json"
SECRETS+=("SECRETKEY")
sandboxed pass "$OWNER_PASS" fund balance --chain "$CHAIN" --wallet guarded
refused "a plaintext indexer on another host is refused" "plaintext"
rm -f "$SANDBOX/.ows/config.json"

# ═══ Outages ══════════════════════════════════════════════════════════════════════════════
say "Outages — a down indexer or proof server, or an untrusted node, fails closed"

# The vault's endpoints, configured as a user does, at a loopback port where nothing listens. Each URL
# carries a credential, which no error may show.
endpoints() {  # endpoints <indexer> <node> <prover>
  printf '{"vault_path":"%s","rpc":{"%s":"%s","%s:node":"%s","%s:prover":"%s"}}\n' \
    "$SANDBOX/.ows" "$CHAIN" "$1" "$CHAIN" "$2" "$CHAIN" "$3" > "$SANDBOX/.ows/config.json"
}
DOWN_INDEXER="http://127.0.0.1:1/api/v4/graphql?project_id=INDEXERKEY"
DOWN_NODE="http://127.0.0.1:1/?apikey=NODEKEY"
DOWN_PROVER="http://127.0.0.1:1/?token=PROVERKEY"
SECRETS+=("INDEXERKEY" "NODEKEY" "PROVERKEY")
mkdir -p "$SANDBOX/.ows"
endpoints "$DOWN_INDEXER" "$DOWN_NODE" "$DOWN_PROVER"

# The guarded wallet's own addresses on $CHAIN, which fund balance shows before it syncs.
ADDRESSES="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_PASSPHRASE="$OWNER_PASS" "$OWS" fund balance \
  --chain "$CHAIN" --wallet guarded </dev/null 2>&1)"
OWN_UNSHIELDED="$(printf '%s\n' "$ADDRESSES" | awk '$1 == "Unshielded:" { print $2 }')"
OWN_SHIELDED="$(printf '%s\n' "$ADDRESSES" | awk '$1 == "Shielded:" { print $2 }')"
[ -n "$OWN_UNSHIELDED" ] && [ -n "$OWN_SHIELDED" ] || { fail "read the guarded wallet's addresses"; exit 1; }
receive() {  # receive <kind> <token type> <recipient> — a makeIntent asking for 5 of a token
  printf '{"method":"makeIntent","desiredInputs":[],"desiredOutputs":[{"kind":"%s","type":"%s","value":"5","recipient":"%s"}],"options":{"intentId":1}}' "$1" "$2" "$3"
}
SHIELDED_TOKEN=0000000000000000000000000000000000000000000000000000000000000000
outage() {  # outage <label> <needle> <tx>
  sandboxed token "$CAP_TOKEN" sign send-tx --chain "$CHAIN" --wallet guarded --json --tx "$3"
  refused "$1" "$2"
}

outage "with every endpoint down, the policy still refuses an over-cap makeIntent" "summed movement 5000000" "$OVER_CAP"
audited "the denial is audited as with the endpoints up" sign_transaction "summed movement 5000000"
outage "a down indexer fails a makeIntent that spends a coin as it is planned, before anything is signed" \
  "failed to connect to Midnight indexer" "$(intent 5)"
outage "a makeTransfer whose indexer cannot confirm the DUST ledger is refused before it is planned" \
  "could not confirm the network's DUST ledger is live" \
  "$(printf '{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"5","recipient":"%s"}]}' "$OWN_UNSHIELDED")"
outage "a down proof server fails a makeIntent's shielded output, before anything is signed" \
  "proof server request failed" "$(receive shielded "$SHIELDED_TOKEN" "$OWN_SHIELDED")"
endpoints "$DOWN_INDEXER" "$DOWN_NODE" "http://10.0.0.5:6300/?token=PROVERKEY"
outage "a plaintext proof server on another host is refused before any witness leaves" \
  "plaintext Midnight proof server" "$(receive shielded "$SHIELDED_TOKEN" "$OWN_SHIELDED")"
# A node that is down is out of reach offline: only a balanced transaction gets that far, and the
# one this unfunded wallet can build offline, an intent asking for funds, is refused as imbalanced
# before the node is contacted. The node's URL is checked first, so an untrusted node is caught.
endpoints "$DOWN_INDEXER" "http://10.0.0.5:9944/?apikey=NODEKEY" "$DOWN_PROVER"
outage "a plaintext node on another host is refused before the signed intent is sent" \
  "plaintext Midnight node" "$(receive unshielded night "$OWN_UNSHIELDED")"

# ═══ Relaying a sealed transaction ════════════════════════════════════════════════════════
say "Submit — submitTransaction relays only a balanced, sealed transaction, with no key"

# A maker offer asking for funds, sealed by sign tx offline: a real sealed transaction that a taker still
# has to complete, so the node would reject it as overspent.
endpoints "$DOWN_INDEXER" "$DOWN_NODE" "$DOWN_PROVER"
OFFER_HEX="$(env -u LWS_PASSPHRASE HOME="$SANDBOX" OWS_PASSPHRASE="$OWNER_PASS" "$OWS" sign tx --chain "$CHAIN" \
  --wallet guarded --json --tx "$(receive unshielded night "$OWN_UNSHIELDED")" </dev/null 2>/dev/null \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["transaction"])' 2>/dev/null)"
[ -n "$OFFER_HEX" ] || { fail "seal a maker offer with sign tx"; exit 1; }
submit() { printf '{"method":"submitTransaction","tx":"%s"}' "$1"; }

sandboxed token "$CAP_TOKEN" sign send-tx --chain "$CHAIN" --wallet guarded --json --tx "$(submit "$OFFER_HEX")"
refused "a token's submitTransaction of a sealed maker offer is refused as imbalanced, before the node" "imbalanced"
sandboxed unset "" sign send-tx --chain "$CHAIN" --wallet guarded --json --tx "$(submit "$OFFER_HEX")"
refused "the same submit with no credential at all is refused the same way" "imbalanced"
sandboxed token "$CAP_TOKEN" sign send-tx --chain "$CHAIN" --wallet guarded --json --tx "$(submit deadbeef)"
refused "a submitTransaction whose tx is not a sealed transaction is refused" "not a sealed"
sandboxed token "$CAP_TOKEN" sign tx --chain "$CHAIN" --wallet guarded --json --tx "$(submit "$OFFER_HEX")"
refused "sign tx refuses a submitTransaction, which has nothing to sign" "send-tx"
rm -f "$SANDBOX/.ows/config.json"

# ═══ Secret hygiene ═══════════════════════════════════════════════════════════════════════
say "Secrets — nothing secret reaches the output or the log"

no_secrets "the audit log holds no token, passphrase or mnemonic" "" && pass "the audit log holds no token, passphrase or mnemonic"

# ═══ Live tier ════════════════════════════════════════════════════════════════════════════
if [ -n "$LIVE" ]; then
  say "LIVE — plan-derived effects against $CHAIN (syncs; nothing is proved or broadcast)"
  WALLET="${WALLET:?LIVE=1 needs WALLET, a funded wallet in your vault}"
  PASS="${PASS:-}"
  LIVE_POLICY="adversarial-live-cap-$$"; LIVE_KEY="adversarial-live-$$"
  live_cleanup() {
    local id
    id="$("$OWS" key list 2>/dev/null | awk -v n="$LIVE_KEY" '/^ID:/{id=$2} /^Name:/{ if ($2==n) print id }')"
    [ -n "$id" ] && "$OWS" key revoke --id "$id" --confirm >/dev/null 2>&1
    "$OWS" policy delete --id "$LIVE_POLICY" --confirm >/dev/null 2>&1
    cleanup
  }
  trap live_cleanup EXIT
  sed "s/\"id\":\"cap\",\"name\":\"cap\"/\"id\":\"$LIVE_POLICY\",\"name\":\"$LIVE_POLICY\"/" "$POLICIES/cap.json" > "$POLICIES/live.json"
  "$OWS" policy create --file "$POLICIES/live.json" >/dev/null 2>&1 || { fail "register the live policy"; exit 1; }
  LIVE_TOKEN="$(OWS_PASSPHRASE="$PASS" "$OWS" key create --name "$LIVE_KEY" --wallet "$WALLET" --policy "$LIVE_POLICY" </dev/null 2>&1 \
    | grep -oE 'ows_key_[A-Za-z0-9_.-]+' | head -1)"
  [ -n "$LIVE_TOKEN" ] || { fail "mint the live token"; exit 1; }
  SECRETS+=("$LIVE_TOKEN")
  # A valid recipient on this network (the BIP-39 test vector's address). Neither live request gets as
  # far as a broadcast, so it never receives anything.
  case "$CHAIN" in
    midnight:preprod) ADDR=mn_addr_preprod1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q49ekgd ;;
    *)                ADDR=mn_addr_preview1dwv2rta0a2skyhrvukaw2q9r2sq6yc4jhj63rf7afxpkrrv6g35q4y8xms ;;
  esac
  live() {  # live <label> <needle> <tx>
    OUT="$(OWS_PASSPHRASE="$LIVE_TOKEN" "$OWS" sign tx --chain "$CHAIN" --wallet "$WALLET" --json --tx "$3" </dev/null 2>&1)"; RC=$?
    refused "$1" "$2"
  }
  transfer() { printf '{"method":"makeTransfer","desiredOutputs":[{"kind":"unshielded","type":"night","value":"%s","recipient":"%s"}]}' "$1" "$2"; }
  live "makeTransfer over the cap is refused at the seam, after planning and before proving" "summed movement" \
    "$(transfer 5000000 "$ADDR")"
  # 10^30 is more than any wallet holds and still fits the ledger's i128 balance check; u128::MAX
  # fails that check's conversion before coin selection can report the shortfall.
  live "a makeTransfer larger than the wallet holds is refused before the gate" "insufficient" \
    "$(transfer 1000000000000000000000000000000 "$ADDR")"
fi

# ── Summary ─────────────────────────────────────────────────────────────────────────────────
echo
if [ "$FAILED" -eq 0 ]; then
  printf '%s%d scenarios held.%s\n' "$BOLD$GREEN" "$PASSED" "$RESET"
  exit 0
fi
printf '%s%d held, %d failed:%s\n' "$BOLD$RED" "$PASSED" "$FAILED" "$RESET"
for f in "${FAILURES[@]}"; do printf '  - %s\n' "$f"; done
exit 1
