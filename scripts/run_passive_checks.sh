#!/usr/bin/env bash
set -euo pipefail
# scripts/run_passive_checks.sh
# Passive scan script — GitHub Actions friendly
# Output: out/raw/*.jsonl , out/evidence/har/*.har , out/triage.txt

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/out"
RAW="$OUT/raw"
EVID="$OUT/evidence/har"
mkdir -p "$RAW" "$EVID" "$OUT/tmp" "$OUT/reads"

TARGETS_FILE="$ROOT/targets.txt"
ORIGIN="http://evil.example"
PATHS=("/v1" "/api" "/graphql" "/status" "/health" "/v2" "/openapi.json" "/swagger.json" "/")

# Clean old
rm -f "$RAW"/*.jsonl "$EVID"/*.har "$OUT/triage.txt" "$OUT/tmp"/*

# Helper: json-escape
jq_escape() { printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

# Build cors.jsonl: one JSON line per host with results array
while read -r host; do
  results_json="[]"
  har_entries="[]"
  for p in "${PATHS[@]}"; do
    url="https://${host}${p}"
    hdrfile="$OUT/tmp/headers_${host//./_}_${p//\//_}.txt"
    bodyfile="$OUT/tmp/body_${host//./_}_${p//\//_}.bin"
    # Passive GET with Origin header, short timeout
    curl -sS -D "$hdrfile" -o "$bodyfile" -H "Origin: $ORIGIN" --max-time 12 "$url" || true
    # parse status
    status=$(awk '/^HTTP/{print $2}' "$hdrfile" | tail -n1 || echo "")
    acao=$(grep -i -m1 '^Access-Control-Allow-Origin:' "$hdrfile" | sed -E 's/^[^:]+:[[:space:]]*//I' | tr -d '\r' || echo "")
    acac=$(grep -i -m1 '^Access-Control-Allow-Credentials:' "$hdrfile" | sed -E 's/^[^:]+:[[:space:]]*//I' | tr -d '\r' || echo "")
    ctype=$(grep -i -m1 '^Content-Type:' "$hdrfile" | sed -E 's/^[^:]+:[[:space:]]*//I' | tr -d '\r' || echo "")
    # body snippet (first 8KB, safe)
    snippet=$(head -c 8192 "$bodyfile" | sed 's/\x0/ /g' | awk '{printf "%s",$0}' || echo "")
    # append to results_json
    result_obj=$(jq -n --arg url "$url" --arg status "$status" --arg aco "$acao" --arg acac "$acac" --arg ctype "$ctype" --arg snippet "$snippet" \
      '{url:$url, status:($status|tonumber? // $status), aco:$aco, acac:$acac, content_type:$ctype, body_snippet:$snippet}')
    results_json=$(jq -c --argjson arr "$results_json" --argjson el "$result_obj" '$arr + [$el]' <<< '[]' | jq -c ". + $results_json" 2>/dev/null || jq -c "[$result_obj]" )
    # simple HAR-lite entry (request/response headers)
    req_headers=$(jq -n --arg method "GET" '{method:$method}' )
    resp_hdrs=$(awk '/^[^ ]+:/ {print}' "$hdrfile" | sed -E 's/: /": "/g' | sed 's/^/"/; s/$/"/' | tr '\n' ',' | sed 's/,$//' )
    # create har entry JSON (minimal)
    har_entry=$(jq -n --arg url "$url" --arg status "$status" --arg ctype "$ctype" --arg aco "$acao" --arg acac "$acac" \
      '{request:{url:$url, method:"GET"}, response:{status:($status|tonumber? // $status), headers:{Content-Type:$ctype, AccessControlAllowOrigin:$aco, AccessControlAllowCredentials:$acac}}}')
    har_entries=$(jq -c --argjson a "$har_entries" --argjson e "$har_entry" '$a + [$e]' <<< '[]' || true)
    # Save body if JSON-ish and 200 (for triage, redaction required before sharing)
    if [[ "$status" == "200" ]] && echo "$ctype" | grep -qi "json"; then
      safefile="$OUT/reads/${host//./_}${p//\//_}.json"
      head -c 65536 "$bodyfile" > "$safefile" || true
      echo "+++ READABLE JSON: $url" >> "$OUT/triage.txt"
      echo "file: $safefile" >> "$OUT/triage.txt"
      echo "---" >> "$OUT/triage.txt"
    fi
    sleep 0.15
  done
  # Write one JSONL line for cors
  jq -n --arg host "$host" --arg module "cors" --argjson results "$results_json" \
    '{host:$host,module:$module,results:$results}' >> "$RAW/cors.jsonl"
  # Write har-lite per host
  if [[ -n "$har_entries" ]]; then
    jq -n --arg host "$host" --argjson entries "$har_entries" '{host:$host,entries:$entries}' > "$EVID/${host}.har"
  fi
done < "$TARGETS_FILE"

# TLS check: cert SANs + issuer + notAfter
while read -r host; do
  cert_pem="$OUT/tmp/${host}_cert.pem"
  # grab cert
  timeout 12 bash -c "echo | openssl s_client -connect ${host}:443 -servername ${host} 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > ${cert_pem}" || true
  if [[ -s "$cert_pem" ]]; then
    sans=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/,$p' | tr -d '\n' | sed -E 's/.*DNS:([^,]+).*/\1/' 2>/dev/null || true)
    issuer=$(openssl x509 -in "$cert_pem" -noout -issuer 2>/dev/null | sed -E 's/issuer= //')
    notafter=$(openssl x509 -in "$cert_pem" -noout -enddate 2>/dev/null | sed -E 's/notAfter=//')
    # try to list DNS entries explicitly
    san_list=$(openssl x509 -in "$cert_pem" -noout -text 2>/dev/null | awk '/Subject Alternative Name/{getline; print}' | sed 's/ *, */,/g' | sed 's/DNS://g' || echo "")
    jq -n --arg host "$host" --arg module "tls" --arg issuer "$issuer" --arg notafter "$notafter" --arg sanlist "$san_list" \
      '{host:$host,module:$module,issuer:$issuer,notAfter:$notafter,subjectAltName:(($sanlist|split(",")))}' >> "$RAW/tls.jsonl"
  else
    jq -n --arg host "$host" --arg module "tls" '{host:$host,module:$module,error:"no-cert"}' >> "$RAW/tls.jsonl"
  fi
done < "$TARGETS_FILE"

# Sessions placeholder: if user has session captures, they should be dropped into out/raw/sessions-source.json and this will normalize; otherwise empty
if [[ -f "$ROOT/out/raw/sessions-source.json" ]]; then
  cp "$ROOT/out/raw/sessions-source.json" "$RAW/sessions.jsonl"
else
  # empty placeholder to indicate missing session captures
  jq -n '{module:"sessions",localStorage:[],cookies:[]}' > "$RAW/sessions.jsonl"
fi

# Discovered APIs: list endpoints where Content-Type is JSON or openapi present
# We will scan the cors.jsonl we created above.
jq -c '. as $line | $line.results[]? | select(.content_type != "" ) | {host:$line.host, url:.url, status:.status, content_type:.content_type}' $RAW/cors.jsonl \
  | jq -s '{module:"discovered_apis",results:.[ ]}' > "$RAW/discovered_apis.jsonl" || echo '{"module":"discovered_apis","results":[]}' > "$RAW/discovered_apis.jsonl"

# Triage summary
echo "TRIAGE SUMMARY" > "$OUT/triage.txt"
echo "=============" >> "$OUT/triage.txt"
echo "" >> "$OUT/triage.txt"
# Count tls entries
tls_count=$(jq -s 'length' "$RAW/tls.jsonl" 2>/dev/null || echo 0)
cors_count=$(jq -s 'length' "$RAW/cors.jsonl" 2>/dev/null || echo 0)
apis_count=$(jq -r '.results|length' "$RAW/discovered_apis.jsonl" 2>/dev/null || echo 0)
echo "TLS entries: $tls_count" >> "$OUT/triage.txt"
echo "CORS results: $cors_count" >> "$OUT/triage.txt"
echo "Discovered API endpoints: $apis_count" >> "$OUT/triage.txt"
echo "" >> "$OUT/triage.txt"

# Quick P0 list: hosts with any aco == "*"
jq -s '.[] | select(.results[]? | .aco=="*") | .host' "$RAW/cors.jsonl" | sed 's/"//g' | while read -r h; do
  echo "P0 candidate: $h (Access-Control-Allow-Origin: *)" >> "$OUT/triage.txt"
done

echo "Done. Outputs are in the out/ directory. IMPORTANT: redact any token values before sharing them here." >> "$OUT/triage.txt"
