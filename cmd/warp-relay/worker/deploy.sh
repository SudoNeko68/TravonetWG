#!/usr/bin/env bash
#
# Deploys the WARP relay Worker through the Cloudflare API without wrangler.
#
# Required environment:
#   CLOUDFLARE_API_TOKEN  scoped token: Account -> Workers Scripts -> Edit,
#                         Account -> Account Settings -> Read
#   CLOUDFLARE_ACCOUNT_ID account id from the dashboard
#   RELAY_TOKEN           shared secret the Android app sends
#
# Optional:
#   SCRIPT_NAME           default: travonet-warp-relay
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?set CLOUDFLARE_ACCOUNT_ID}"
: "${RELAY_TOKEN:?set RELAY_TOKEN}"

SCRIPT_NAME="${SCRIPT_NAME:-travonet-warp-relay}"
API="https://api.cloudflare.com/client/v4"

fail() {
    echo "error: $*" >&2
    exit 1
}

check_response() {
    python3 -c '
import json
import sys

data = json.load(sys.stdin)
if not data.get("success"):
    details = data.get("errors") or data.get("messages") or data
    print("Cloudflare API error:", json.dumps(details, ensure_ascii=False), file=sys.stderr)
    sys.exit(1)
' || fail "Cloudflare API request failed"
}

echo ">>> checking token"
verify="$(curl -sS -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "$API/user/tokens/verify")"
printf '%s' "$verify" | check_response

echo ">>> uploading $SCRIPT_NAME"
upload="$(curl -sS -X PUT \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -F 'metadata={"main_module":"warp-relay.js"};type=application/json' \
    -F 'warp-relay.js=@warp-relay.js;type=application/javascript+module' \
    "$API/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$SCRIPT_NAME")"
printf '%s' "$upload" | check_response

echo ">>> setting RELAY_TOKEN"
secret_payload="$(python3 -c '
import json
import os
print(json.dumps({
    "name": "RELAY_TOKEN",
    "text": os.environ["RELAY_TOKEN"],
    "type": "secret_text",
}))
')"
secret="$(curl -sS -X PUT \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data "$secret_payload" \
    "$API/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/$SCRIPT_NAME/secrets")"
printf '%s' "$secret" | check_response >/dev/null

echo ">>> reading workers.dev subdomain"
subdomain_response="$(curl -sS \
    -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
    "$API/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/subdomain")"
printf '%s' "$subdomain_response" | check_response >/dev/null

subdomain="$(printf '%s' "$subdomain_response" | python3 -c '
import json
import sys
data = json.load(sys.stdin)
print((data.get("result") or {}).get("subdomain") or "")
')"
if [ -z "$subdomain" ]; then
    fail "the account has no workers.dev subdomain; set it once in the dashboard (Workers & Pages -> Settings)"
fi

url="https://$SCRIPT_NAME.$subdomain.workers.dev/register"
echo
echo "Worker URL: $url"
echo

echo ">>> test registration"
public_key="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
test_response="$(curl -sS -m 45 -X POST "$url" \
    -H 'Content-Type: application/json' \
    -H "X-Relay-Token: $RELAY_TOKEN" \
    --data "{\"public_key\":\"$public_key\",\"locale\":\"ru-RU\",\"model\":\"TravonetWG test\"}" \
    -w '\nHTTP %{http_code}\n')"
printf '%s\n' "$test_response" | head -c 800
echo
if printf '%s' "$test_response" | grep -q 'HTTP 200'; then
    echo "OK: registration works. Use this URL and RELAY_TOKEN in the app."
else
    fail "the Worker is deployed, but the test registration failed; see the response above"
fi
