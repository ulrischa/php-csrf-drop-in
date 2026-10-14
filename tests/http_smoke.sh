#!/usr/bin/env bash
set -euo pipefail

# Run the example through a real PHP HTTP server and preserve its session cookie.
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
work_dir="$(mktemp -d)"
port="$(php -r 'echo random_int(20000, 50000);')"
server_pid=""

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

php -S "127.0.0.1:$port" -t "$root_dir" > "$work_dir/server.log" 2>&1 &
server_pid="$!"
url="http://127.0.0.1:$port/examples/contact.php"

# Wait for the test server.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS -c "$work_dir/cookies" "$url" > "$work_dir/form.html" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if [[ ! -s "$work_dir/form.html" ]]; then
    cat "$work_dir/server.log" >&2
    exit 1
fi

token="$(sed -n 's/.*name="_csrf" value="\([a-f0-9]*\)".*/\1/p' "$work_dir/form.html")"
[[ "$(printf '%s' "$token" | wc -c)" -eq 64 ]] || { echo 'Missing CSRF hidden field' >&2; exit 1; }

valid_status="$(curl -sS -b "$work_dir/cookies" -o "$work_dir/valid.html" -w '%{http_code}' \
    --data-urlencode "_csrf=$token" --data-urlencode 'name=Alice' "$url")"
[[ "$valid_status" == '200' ]] || exit 1
grep -q 'Form submitted successfully' "$work_dir/valid.html"

repeat_status="$(curl -sS -b "$work_dir/cookies" -o "$work_dir/repeat.html" -w '%{http_code}' \
    --data-urlencode "_csrf=$token" --data-urlencode 'name=Bob' "$url")"
[[ "$repeat_status" == '200' ]] || exit 1

invalid_status="$(curl -sS -b "$work_dir/cookies" -o "$work_dir/invalid.html" -w '%{http_code}' \
    --data-urlencode '_csrf=invalid' --data-urlencode 'name=Alice' "$url")"
[[ "$invalid_status" == '403' ]] || exit 1
grep -q 'security token is invalid' "$work_dir/invalid.html"

missing_status="$(curl -sS -b "$work_dir/cookies" -o "$work_dir/missing.html" -w '%{http_code}' \
    --data-urlencode 'name=Alice' "$url")"
[[ "$missing_status" == '403' ]] || exit 1

escaped_status="$(curl -sS -b "$work_dir/cookies" -o "$work_dir/escaped.html" -w '%{http_code}' \
    --data-urlencode "_csrf=$token" --data-urlencode 'name=<script>alert(1)</script>' "$url")"
[[ "$escaped_status" == '200' ]] || exit 1
grep -q '&lt;script&gt;alert(1)&lt;/script&gt;' "$work_dir/escaped.html"
if grep -q '<script>alert(1)</script>' "$work_dir/escaped.html"; then
    exit 1
fi

echo 'HTTP smoke tests passed.'
