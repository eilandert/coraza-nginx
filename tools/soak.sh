#!/usr/bin/env bash
#
# Sustained mixed-load soak for the coraza-nginx connector. Drives a real
# nginx (ideally an ASan/UBSan build, optionally under valgrind memcheck or
# helgrind) with concurrent benign AND attack-shaped requests for a fixed
# duration, then asserts the worker survived cleanly: no sanitizer report,
# no valgrind/helgrind error, no crash, no leak, no error-log [alert]/[emerg].
#
# The traffic mix deliberately exercises the WAF decision path in both
# directions — benign requests that must pass (200) and attack requests the
# in-config SecRules must block (403) — across nine request shapes that drive
# every attacker-reachable pure-C connector path under the checker:
#   * URI-arg, request-body, and request-HEADER attacks (phase 1/2 deny)
#   * benign GET, POST, and large response body (pass)
#   * large CHUNKED request body -> file-backed body_filter buffer chain
#   * 40 large request headers -> ngx_str_to_char loop across ngx_list parts
#   * RESPONSE_BODY inspection, both pass and phase-4 deny (body_filter clone)
# so allocation/free of the Coraza transaction, header forwarding
# (ngx_str_to_char), and request/response body inspection all run every
# iteration. Deep coverage of THIS connector lives here (memcheck/helgrind),
# not in the fuzzer — the fuzzable pure-C leaf is just ngx_str_to_char; the
# rest of the connector needs a live nginx request, which is what this drives.
#
# Requires libcoraza installed (dlopen'd at runtime; see README). The nginx
# binary passed in must have been built --add-dynamic-module against this
# tree and be able to load libcoraza (LD_LIBRARY_PATH=/usr/local/lib if that
# is where `make install` put it).
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 120 8
#   USE_HELGRIND=1 tools/soak.sh <nginx-binary> 120 8
#
# Exit non-zero on ANY of: sanitizer error, valgrind/helgrind error, nginx
# crash/non-clean exit, error-log alert/emerg, or a WAF verdict regression
# (benign blocked / attack allowed).

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"
MODULE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

WORK="$(mktemp -d)"

# Arm the cleanup trap IMMEDIATELY after mktemp -d, before any code that can
# exit: the SOAK_PORT validation and pick_port below both bail out, and an
# unarmed trap would leave the temp directory behind on every such run.
# Kill the whole process GROUP, not just the master: nginx workers are children
# and survive a kill of the master alone, keeping the listening socket open and
# making every later run fail. The server is launched under setsid below, so
# NGINX_PID doubles as the process-group id. The ${NGINX_PID:-} guard makes this
# safe to arm long before the server starts.
cleanup() {
    if [ -n "${NGINX_PID:-}" ]; then
        kill -9 -- "-${NGINX_PID}" 2>/dev/null || kill -9 "${NGINX_PID}" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# mktemp -d is 0700. Under root the nginx workers drop to an unprivileged user
# (nobody) which then cannot traverse WORK, so every request 403s and readiness
# reports a misleading "never came up". 0755 is what nginx needs; the soak only
# writes non-secret generated fixtures here (random/base64 bodies and an
# nginx.conf carrying no credentials), so widening traverse leaks nothing.
# Refusing to run as root instead would make the container/CI root case — the
# common one — simply unusable.
chmod 0755 "$WORK"

# Pick a free port dynamically. The previous fixed 18223 collided with any
# leftover worker from an earlier run, producing the same misleading
# "never came up" whose real cause was bind(): Address already in use.
#
# Deliberately pure bash (/dev/tcp), not python3: this script's documented
# dependency set is bash/curl/nginx, and it has to run in minimal containers
# where no interpreter is installed.
#
# NOTE: this only proves the port was free when probed. Nothing holds it until
# nginx bind()s some hundreds of ms later, so a racing process can still take
# it. That window is not closable from a shell; it degrades to a clear
# "did not bind" failure rather than a false pass, and the caller can pin a
# port with SOAK_PORT. try_port() below retries the whole start sequence.
pick_port() {
    local p
    # A bash built without net redirections fails EVERY /dev/tcp connect, which
    # would make the probe below read "free" for every candidate and hand back
    # a possibly-busy port with no check at all. bash distinguishes the two:
    # a real refusal is ENOENT-free ("connect: Connection refused") while the
    # missing feature reports the pseudo-path as absent ("No such file or
    # directory"). LC_ALL=C pins the wording, which is otherwise localized.
    if LC_ALL=C bash -c '(exec 3<>/dev/tcp/127.0.0.1/1)' 2>&1 \
       | grep -q 'No such file or directory'; then
        echo "FAIL: this bash cannot open /dev/tcp (built without net" \
             "redirections), so a free port cannot be detected;" \
             "set SOAK_PORT explicitly" >&2
        return 1
    fi
    for _ in $(seq 1 100); do
        # 20000-29999: above the common fixed-service range, below the default
        # ephemeral range (32768+) so we rarely collide with an outbound socket.
        p=$(( 20000 + (RANDOM % 10000) ))
        # A refused connection means nothing is listening -> candidate is free.
        (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3>&- 2>/dev/null; continue; }
        printf '%s\n' "$p"
        return 0
    done
    echo "FAIL: could not find a free port in 20000-29999 after 100 tries" >&2
    return 1
}

if [ -n "${SOAK_PORT:-}" ]; then
    # Validated because $PORT is interpolated into the generated nginx.conf
    # below; an unchecked value would let a caller inject config directives.
    case "$SOAK_PORT" in
        ''|*[!0-9]*)
            echo "FAIL: SOAK_PORT must be a number, got '$SOAK_PORT'" >&2; exit 2 ;;
    esac
    if [ "$SOAK_PORT" -lt 1 ] || [ "$SOAK_PORT" -gt 65535 ]; then
        echo "FAIL: SOAK_PORT out of range (1-65535), got '$SOAK_PORT'" >&2; exit 2
    fi
    PORT="$SOAK_PORT"
else
    PORT="$(pick_port)" || exit 1
fi
BASE="http://127.0.0.1:$PORT"

# Widening the directories is not enough on its own: the fixtures written into
# them inherit the caller's umask, so under a restrictive one (umask 077 -> mode
# 0600) the workers can traverse the tree but still cannot READ index.html et
# al, which reproduces the very 403 this is meant to fix. Set the umask for
# everything created from here on rather than chmod-ing each file.
umask 022
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"
chmod 0755 "$WORK/conf" "$WORK/logs" "$WORK/html"

echo "hello coraza" > "$WORK/html/index.html"
head -c 200000 /dev/urandom | base64 > "$WORK/html/medium"
# Benign response body scanned by the phase-4 RESPONSE_BODY rule (must pass).
head -c 120000 /dev/urandom | base64 > "$WORK/html/respbody"
# Response body carrying the leak marker (must be blocked 403 at phase 4).
{ head -c 40000 /dev/urandom | base64; echo "leakmarker"; } > "$WORK/html/leak"

# Locate the built module (.so). --add-dynamic-module builds it into objs/;
# if the caller installed it, allow an override via $CORAZA_MODULE_SO.
MODULE_SO="${CORAZA_MODULE_SO:-}"
if [ -z "$MODULE_SO" ]; then
    MODULE_SO="$(dirname "$NGINX")/ngx_http_coraza_module.so"
fi
LOAD_MODULE_DIRECTIVE=""
if [ -f "$MODULE_SO" ]; then
    LOAD_MODULE_DIRECTIVE="load_module $MODULE_SO;"
fi

# In-config SecRules: block a URI-arg attack marker and a request-body
# marker so both the header/URI path and the body-inspection path are
# exercised. Benign traffic hits neither.
cat > "$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE_DIRECTIVE
daemon off;
master_process on;
worker_processes 4;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;
        default_type text/plain;

        # Small body buffer so the large chunked upload spills to a temp file,
        # exercising the connector's file-backed request-body inspection path.
        client_body_buffer_size 16k;
        # Headroom for the many-large-headers traffic shape (40 headers).
        large_client_header_buffers 8 16k;
        coraza on;
        coraza_rules 'SecRuleEngine On
                      SecRequestBodyAccess On
                      SecResponseBodyAccess On
                      SecResponseBodyMimeType text/plain text/html
                      SecRule ARGS "@rx attackmarker" "id:100,phase:2,deny,status:403"
                      SecRule REQUEST_BODY "@rx evilbody" "id:101,phase:2,deny,status:403"
                      SecRule REQUEST_HEADERS:X-Attack "@rx headermarker" "id:102,phase:1,deny,status:403"
                      SecRule RESPONSE_BODY "@rx leakmarker" "id:103,phase:4,deny,status:403"
                      ';

        # The static handler rejects POST with 405; the soak POSTs benign
        # bodies (must pass) and attack bodies (Coraza denies 403 in phase 2,
        # before the handler). Route POSTs that survive the WAF to a 200 so a
        # clean benign body is a 200, not a spurious 405.
        error_page 405 = @ok;
        location @ok { return 200 "ok\n"; }

        location / { }
        location /medium { alias $WORK/html/medium; }
        # Response-body inspect target: served content is scanned by the
        # phase-4 RESPONSE_BODY rule above, exercising the body_filter copy/
        # clone + buffered-inspection path (pure-C connector code).
        location /respbody { alias $WORK/html/respbody; }
        # A response carrying the leak marker MUST be blocked at phase 4,
        # driving the response-body deny path end to end.
        location /leak { alias $WORK/html/leak; }
        # Redirect path: exercises header_filter resolv_* + the entity-header
        # clearing the connector does when Coraza rewrites Location.
        location /redir { return 302 /medium; }
    }
}
EOF

# detect_odr_violation=0: nginx defines ngx_module_names/ngx_modules in BOTH
# the main binary and the dynamic module .so (build artifact of
# --add-dynamic-module) — ASan flags the duplicate global as an ODR violation
# and aborts at load. It is benign nginx dynamic-module duplication, not a bug.
ASAN_OPTIONS="${ASAN_OPTIONS:-}:detect_leaks=1:abort_on_error=1:exitcode=42:detect_odr_violation=0:log_path=$WORK/logs/asan"
export ASAN_OPTIONS
# UBSan recovers (halt_on_error=0) so nginx-core's benign init nullability
# trips don't kill startup; real UB is still logged to ubsan* and asserted
# below. print the stack for triage.
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-}:print_stacktrace=1:halt_on_error=0:log_path=$WORK/logs/ubsan"
# libcoraza is usually installed under /usr/local/lib.
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib}:/usr/local/lib"

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    RUN=(valgrind --error-exitcode=99 --leak-check=full
         --errors-for-leak-kinds=definite
         --suppressions="$MODULE_DIR/valgrind.suppress"
         --log-file="$WORK/logs/valgrind.%p" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    RUN=(valgrind --tool=helgrind --error-exitcode=99
         --suppressions="$MODULE_DIR/valgrind.suppress"
         --log-file="$WORK/logs/helgrind.%p" "${RUN[@]}")
fi

# Capture nginx (and valgrind) stderr — config-parse / dlopen(libcoraza)
# failures print HERE, before error.log is ever opened.
# setsid puts the server in its own process group so the EXIT trap can signal
# the master AND every worker with one kill on the negated pid. Verified that
# `setsid cmd &` yields $! == pgid and that the negated kill reaps leader and
# children together.
#
# setsid is util-linux, not bash, so it may be absent from a minimal image.
# Fall back to running the server directly: the group kill then degenerates to
# the single-pid kill in cleanup(), which is the old (leaky) behaviour, but a
# missing setsid must not make the soak unrunnable.
if command -v setsid >/dev/null 2>&1; then
    SETSID=(setsid)
else
    echo "warning: setsid not found — workers may survive cleanup" >&2
    SETSID=()
fi
"${SETSID[@]}" "${RUN[@]}" >"$WORK/logs/stdout.txt" 2>"$WORK/logs/stderr.txt" &
NGINX_PID=$!

# Wait for listen. valgrind + the cgo Go runtime start slowly, so allow up
# to ~120s; bail early if the process already died (config error, missing
# libcoraza, etc.) rather than burning the full timeout.
up=0
bound=0
died=0
for _ in $(seq 1 1200); do
    if ! kill -0 "$NGINX_PID" 2>/dev/null; then
        died=1
        break   # process gone — startup failed, report below
    fi
    # Track bind and answer separately so the failure message can say which of
    # the two did not happen, instead of one catch-all "never came up".
    # The (exec 3<>...) runs in a subshell, so fd 3 is opened and closed there;
    # the parent never holds it and needs no cleanup of its own.
    if [ "$bound" -ne 1 ] && (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
        bound=1
    fi
    curl -fsS -o /dev/null "$BASE/" 2>/dev/null && { up=1; bound=1; break; }
    sleep 0.1
done
if [ "$up" -ne 1 ]; then
    if [ "$died" -eq 1 ]; then
        echo "FAIL: nginx exited during startup (never bound port $PORT)"
    elif [ "$bound" -ne 1 ]; then
        echo "FAIL: nginx did not bind port $PORT (process alive; check bind()/permissions)"
    else
        echo "FAIL: nginx bound port $PORT but did not answer a request"
    fi
    echo "--- stderr ---"; cat "$WORK/logs/stderr.txt" 2>/dev/null || true
    echo "--- error.log ---"; cat "$WORK/logs/error.log" 2>/dev/null || echo "(none written)"
    # valgrind/helgrind print startup aborts to their own --log-file, not
    # stderr — dump them too or a sub-second crash shows nothing.
    if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
        echo "--- valgrind/helgrind log ---"
        cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
    fi
    kill "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

echo "soak: ${DURATION}s, concurrency ${CONC}, port ${PORT}$( [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'; [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)')"
END=$(( $(date +%s) + DURATION ))
fail=0

# A large body forces nginx to buffer the request into a temp file, driving
# the connector's body_filter temp-file/multi-buffer chain path (not just the
# in-memory single-buffer case a tiny -d body hits).
BIG_BODY="$WORK/html/bigreq"
head -c 300000 /dev/urandom | base64 > "$BIG_BODY"

worker() {
    while [ "$(date +%s)" -lt "$END" ]; do
        case $((RANDOM % 9)) in
        0)  # benign GET -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign GET got $code"; return 1; } ;;
        1)  # benign larger response body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "$BASE/medium" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign /medium got $code"; return 1; } ;;
        2)  # URI-arg attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "$BASE/?q=attackmarker" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "URI attack got $code (want 403)"; return 1; } ;;
        3)  # request-body attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=evilbody' \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "body attack got $code (want 403)"; return 1; } ;;
        4)  # benign POST body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -d 'x=harmless' \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "benign POST got $code"; return 1; } ;;
        5)  # large chunked request body -> temp-file buffer chain, must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -H 'Transfer-Encoding: chunked' \
                   --data-binary "@$BIG_BODY" \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "large chunked body got $code"; return 1; } ;;
        6)  # many + large request headers -> ngx_str_to_char per-header loop
            #                                  across multiple ngx_list parts
            hdrs=(); for i in $(seq 1 40); do hdrs+=(-H "X-H$i: v$i-$(head -c 64 /dev/zero | tr '\0' a)"); done
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   "${hdrs[@]}" \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || { echo "many-headers got $code"; return 1; } ;;
        7)  # request-header attack -> phase-1 header rule, must block 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   -H 'X-Attack: headermarker' \
                   "$BASE/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || { echo "header attack got $code (want 403)"; return 1; } ;;
        8)  # response-body: benign scanned body passes, leak marker blocks 403
            if [ $((RANDOM % 2)) -eq 0 ]; then
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                       "$BASE/respbody" 2>/dev/null || echo 000)
                [ "$code" = "200" ] || { echo "benign respbody got $code"; return 1; }
            else
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                       "$BASE/leak" 2>/dev/null || echo 000)
                [ "$code" = "403" ] || { echo "resp leak got $code (want 403)"; return 1; }
            fi ;;
        esac
    done
}

pids=()
for _ in $(seq 1 "$CONC"); do worker & pids+=($!); done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool cleanups (incl. the Coraza transaction) run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null; rc=$?

problems=0
if ls "$WORK"/logs/asan* >/dev/null 2>&1; then
    echo "FAIL: ASan report:"; cat "$WORK"/logs/asan*; problems=1
fi
# UBSan noise from nginx core / third-party init (benign nullability trips
# gcc can't scope out) is print-only. A diagnostic whose source location is
# in OUR src/ is real UB in the connector's pure-C paths and fails the soak.
# Do not match connector frames deeper in a third-party diagnostic's stack:
# those identify a caller, not the source location that triggered UBSan. The
# fuzz job also gates those paths, but the soak drives the live-nginx call sites
# the fuzzer can't reach.
if ls "$WORK"/logs/ubsan* >/dev/null 2>&1; then
    echo "note: UBSan diagnostics:"
    cat "$WORK"/logs/ubsan*
	# Resolved from the runtime module root.
	# shellcheck disable=SC1091
	source "$MODULE_DIR/tools/ubsan-owned-pattern.sh"
	UBSAN_OWNED_PATTERN="$(ubsan_owned_pattern "$MODULE_DIR")"
    ubsan_grep_rc=0
    grep -qE "$UBSAN_OWNED_PATTERN" "$WORK"/logs/ubsan* || ubsan_grep_rc=$?
    if [ "$ubsan_grep_rc" -eq 0 ]; then
        echo "FAIL: UBSan diagnostic from our src/ (see above)"; problems=1
    elif [ "$ubsan_grep_rc" -ne 1 ]; then
        echo "FAIL: could not inspect UBSan diagnostics"; problems=1
    fi
fi
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"; problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a WAF verdict regression"; problems=1
fi
# QUIT is a clean exit; valgrind uses 99, ASAN 42 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"; tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

[ "$problems" -ne 0 ] && exit 1
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no sanitizer/leak/crash, WAF verdicts held"
