#!/usr/bin/env bash
#
# Forced-temp-file request-body latency benchmark for the coraza-nginx
# connector.
#
# WHAT IT MEASURES
#
# ngx_http_coraza_append_request_body_file() (src/ngx_http_coraza_pre_access.c)
# runs SYNCHRONOUSLY on the worker thread whenever nginx has spilled the
# request body to a temp file. Per invocation it opens a second descriptor by
# name, allocates one 64 KiB chunk buffer, then loops:
#
#     ngx_read_file()                  -> blocking read(2)/pread(2)
#     coraza_append_request_body()     -> cgo crossing
#     coraza_process_intervention()    -> another cgo crossing (non-final chunks)
#
# The open question this benchmark exists to settle is whether that loop is
# worth moving off the worker thread (thread pool / aio). Answering it needs
# the read loop separated from two costs it is easily confused with:
#
#   * the engine's own body processing (parsing/buffering the body inside
#     libcoraza), which happens identically whether the bytes came from memory
#     or from a file, and
#   * nginx's spill (writing the temp file), which the request pays whether or
#     not the connector ever reads it back.
#
# METHOD -- FOUR ARMS
#
# Same nginx binary, one worker, one keepalive connection, requests issued
# serially. This is a LATENCY benchmark of a synchronous code path; adding
# concurrency would measure queueing instead.
#
#   B      coraza on, SecRequestBodyAccess Off, client_body_in_file_only on
#          -> connector runs (transaction, headers, phases) and nginx spills
#             the body to disk, but the connector never opens or reads it.
#
#   CMEM   coraza on, SecRequestBodyAccess On, client_body_buffer_size 32m
#          -> identical rules and identical engine body processing, but the
#             body stays in memory so the file read loop NEVER RUNS.
#
#   CFILE  coraza on, SecRequestBodyAccess On, client_body_in_file_only on
#          -> the code under test.
#
#   The two differences that matter:
#     CFILE - CMEM  = the synchronous temp-file read loop, and nothing else.
#                     Same engine, same rules, same body, same phases.
#     CMEM  - B     = the engine's body processing cost, which no amount of
#                     threading the read loop can remove.
#
# Every arm proxies to a local sink over a UNIX SOCKET. Both details are
# load-bearing:
#
#   * A `return 200` handler runs in the REWRITE phase, before PREACCESS, so
#     the connector's pre-access handler never runs and the benchmark would
#     silently measure nothing. A real content handler is required.
#   * A TCP loopback sink stalls ~21 ms per request on sub-64 KiB bodies
#     (delayed ACK on the upstream leg). That artefact is ~200x the signal.
#     A unix socket removes it. Do not "simplify" this back to 127.0.0.1.
#
# The `ctl:requestBodyProcessor=URLENCODED` SecAction pins the body processor
# explicitly. The driver sends application/x-www-form-urlencoded, so libcoraza
# would select URLENCODED from the Content-Type anyway (verified by mutation:
# removing the SecAction changes nothing) -- it is kept so the measured engine
# cost does not silently change if that content-type inference ever does.
#
# What IS load-bearing is a real REQUEST_BODY rule: without one libcoraza can
# report the body as inaccessible, the connector skips it entirely, and every
# arm measures the same thing. The controls below assert the arms are live
# before any timing runs, and both have been observed failing on a mutant.
#
# NOISE FLOOR
#
# The project's A/B harness noise floor is +/-2%. This script interleaves the
# arms round-robin (not arm-at-a-time) so drift hits every arm equally, runs
# ROUNDS repetitions, reports the median per cell and the observed spread, and
# refuses to let a difference smaller than that spread be read as a result.
#
# USAGE
#
#   tools/bench-request-tempfile.sh <nginx-binary> [rounds] [requests-per-cell]
#
# The nginx binary must have been built --add-dynamic-module against this tree
# and be able to dlopen libcoraza (LD_LIBRARY_PATH=/usr/local/lib if that is
# where `make install` put it). Build it as .github/versions.env pins it:
#
#   ./configure --with-compat --with-threads --with-http_ssl_module \
#       --with-http_v2_module --with-http_realip_module \
#       --with-http_auth_request_module \
#       --add-dynamic-module=<this checkout> \
#       --with-cc-opt="-O2 -g -fno-omit-frame-pointer -Wno-unused-function"
#
# Environment:
#   CORAZA_MODULE_SO   override the module .so path
#   BENCH_SIZES        body-size sweep (default "32k 64k 128k 1m 8m")
#   BENCH_PORT         listen port (default 18224)

set -euo pipefail

NGINX="${1:?usage: bench-request-tempfile.sh <nginx-binary> [rounds] [reqs-per-cell]}"
ROUNDS="${2:-5}"
REQS="${3:-100}"
PORT="${BENCH_PORT:-18224}"
SIZES="${BENCH_SIZES:-32k 64k 128k 1m 8m}"
ARMS="b cmem cfile"

command -v curl >/dev/null || { echo "FAIL: curl not found"; exit 1; }
command -v python3 >/dev/null || { echo "FAIL: python3 not found"; exit 1; }

WORK="$(mktemp -d)"
trap 'kill -9 "${NGINX_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs"

MODULE_SO="${CORAZA_MODULE_SO:-$(dirname "$NGINX")/ngx_http_coraza_module.so}"
LOAD_MODULE_DIRECTIVE=""
[ -f "$MODULE_SO" ] && LOAD_MODULE_DIRECTIVE="load_module $MODULE_SO;"

declare -A BODY_BYTES
for s in $SIZES; do
    case "$s" in
        *k|*K) n=$(( ${s%[kK]} * 1024 )) ;;
        *m|*M) n=$(( ${s%[mM]} * 1024 * 1024 )) ;;
        *)     n="$s" ;;
    esac
    BODY_BYTES[$s]="$n"
done

# The rule set is deliberately minimal: a body processor plus one always-false
# REQUEST_BODY regex. We are measuring the connector, not CRS matching cost.
# The regex must be a genuine REQUEST_BODY rule -- it is what makes libcoraza
# report the body as accessible, which is what makes the connector read it.
BODY_RULES='SecRuleEngine On
                      SecRequestBodyAccess On
                      SecRequestBodyLimit 67108864
                      SecRequestBodyNoFilesLimit 67108864
                      SecRequestBodyLimitAction ProcessPartial
                      SecResponseBodyAccess Off
                      SecAction "id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
                      SecRule REQUEST_BODY "@rx zzzbenchmarkermarkerzzz" "id:201,phase:2,deny,status:403"'

cat > "$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE_DIRECTIVE
daemon off;
master_process off;
worker_processes 1;
error_log $WORK/logs/error.log crit;
pid $WORK/logs/nginx.pid;
events { worker_connections 256; }
http {
    access_log off;
    client_body_temp_path $WORK/body_temp;
    client_max_body_size 64m;
    keepalive_requests 1000000;
    keepalive_timeout 60s;
    default_type text/plain;

    upstream bench_sink { server unix:$WORK/sink.sock; }

    # The sink exists only so the arms have a real content handler that
    # consumes the request body. coraza is off here, so the upstream leg
    # costs every arm the same.
    server {
        listen unix:$WORK/sink.sock;
        coraza off;
        location / { return 200 "ok\n"; }
    }

    # Arm B: connector runs, body spills to disk, connector never reads it.
    server {
        listen 127.0.0.1:$PORT;
        server_name b;
        client_body_in_file_only on;
        coraza on;
        coraza_rules 'SecRuleEngine On
                      SecRequestBodyAccess Off
                      SecResponseBodyAccess Off
                      SecRule REQUEST_HEADERS:X-Zz "@rx zzzbenchmarkermarkerzzz" "id:202,phase:1,deny,status:403"
                      ';
        location / { proxy_pass http://bench_sink; }
    }

    # Arm CMEM: identical inspection, body never leaves memory.
    server {
        listen 127.0.0.1:$PORT;
        server_name cmem;
        client_body_buffer_size 32m;
        coraza on;
        coraza_rules '$BODY_RULES
                      ';
        location / { proxy_pass http://bench_sink; }
    }

    # Arm CFILE: the code under test.
    server {
        listen 127.0.0.1:$PORT;
        server_name cfile;
        client_body_in_file_only on;
        coraza on;
        coraza_rules '$BODY_RULES
                      ';
        location / { proxy_pass http://bench_sink; }
    }
}
EOF

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-/usr/local/lib}:/usr/local/lib"

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" \
    >"$WORK/logs/stdout.txt" 2>"$WORK/logs/stderr.txt" &
NGINX_PID=$!

up=0
for _ in $(seq 1 600); do
    kill -0 "$NGINX_PID" 2>/dev/null || break
    curl -fsS -o /dev/null -H 'Host: b' "http://127.0.0.1:$PORT/" 2>/dev/null \
        && { up=1; break; }
    sleep 0.1
done
if [ "$up" -ne 1 ]; then
    echo "FAIL: nginx never came up"
    echo "--- stderr ---"; cat "$WORK/logs/stderr.txt" 2>/dev/null || true
    echo "--- error.log ---"; cat "$WORK/logs/error.log" 2>/dev/null || echo "(none)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Controls, run BEFORE any timing. Each one guards a way this benchmark can
# silently measure nothing at all; every one of them has actually happened
# while this script was being written.
# ---------------------------------------------------------------------------

status() {   # status <host> <body>
    curl -s -o /dev/null -w '%{http_code}' -H "Host: $1" -H 'Expect:' \
        --data-binary "$2" "http://127.0.0.1:$PORT/" 2>/dev/null || echo 000
}

# 1. POSITIVE control: the inspecting arms must actually block a marker body.
#    If they return 200 the engine is not looking at the body and CFILE-CMEM
#    would be a comparison of two identical no-ops.
for h in cmem cfile; do
    code=$(status "$h" 'x=zzzbenchmarkermarkerzzz')
    if [ "$code" != "403" ]; then
        echo "FAIL: arm $h returned $code for a marker body (want 403)."
        echo "      The engine is NOT inspecting the request body, so this"
        echo "      benchmark would measure nothing. Refusing to report."
        exit 1
    fi
done

# 2. NEGATIVE control: the non-inspecting arm must NOT block the same body.
#    If arm B blocked it, B would not be the body-access-off baseline it
#    claims to be and CMEM-B would be meaningless.
code=$(status b 'x=zzzbenchmarkermarkerzzz')
if [ "$code" = "403" ]; then
    echo "FAIL: arm b blocked a marker body; it is inspecting the body and"
    echo "      is therefore not a valid SecRequestBodyAccess Off baseline."
    exit 1
fi

# 3. Clean bodies must pass everywhere, or the timings would be measuring
#    the 403 short-circuit rather than a full inspection.
for h in $ARMS; do
    code=$(status "$h" 'x=harmless')
    [ "$code" = "200" ] || { echo "FAIL: arm $h returned $code for a clean body"; exit 1; }
done

# 4. The forcing mechanism itself. client_body_in_file_only on makes nginx
#    keep the spilled file, so a spill leaves an observable artifact. If the
#    file-backed arms are not spilling, CFILE is not running the code under
#    test at all.
mkdir -p "$WORK/body_temp"
find "$WORK/body_temp" -type f -delete 2>/dev/null || true
head -c "${BODY_BYTES[${SIZES%% *}]}" /dev/zero | tr '\0' a > "$WORK/probe"
curl -s -o /dev/null -H 'Host: cfile' -H 'Expect:' --data-binary "@$WORK/probe" \
    "http://127.0.0.1:$PORT/" >/dev/null 2>&1 || true
spilled=$(find "$WORK/body_temp" -type f 2>/dev/null | wc -l)
if [ "$spilled" -lt 1 ]; then
    echo "FAIL: no temp file appeared under $WORK/body_temp for a cfile request."
    echo "      Bodies are NOT spilling to disk, so arm cfile is not exercising"
    echo "      ngx_http_coraza_append_request_body_file()."
    exit 1
fi
find "$WORK/body_temp" -type f -delete 2>/dev/null || true

# ---------------------------------------------------------------------------
# Driver. One keepalive connection, TCP_NODELAY, headers and body in a single
# sendall so the client cannot introduce its own pacing artefacts. Reports
# microseconds per request.
# ---------------------------------------------------------------------------
cat > "$WORK/drive.py" <<'PYEOF'
import socket, sys, time

host, port, vhost, n, reqs = (sys.argv[1], int(sys.argv[2]), sys.argv[3],
                              int(sys.argv[4]), int(sys.argv[5]))
body = b'x=' + b'a' * (n - 2)
head = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: "
        "application/x-www-form-urlencoded\r\nContent-Length: %d\r\n"
        "Connection: keep-alive\r\n\r\n" % (vhost, len(body))).encode()
msg = head + body

s = socket.create_connection((host, port))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def one():
    s.sendall(msg)
    buf = b''
    while b'\r\n\r\n' not in buf:
        d = s.recv(65536)
        if not d:
            raise SystemExit('FAIL: upstream closed the connection')
        buf += d
    hdr, rest = buf.split(b'\r\n\r\n', 1)
    cl = 0
    for line in hdr.split(b'\r\n')[1:]:
        if line.lower().startswith(b'content-length:'):
            cl = int(line.split(b':')[1])
    while len(rest) < cl:
        rest += s.recv(65536)
    return hdr.split(b'\r\n')[0]


st = one()
if b' 200' not in st:
    raise SystemExit('FAIL: driver got %r, expected 200' % st)
t0 = time.perf_counter_ns()
for _ in range(reqs):
    one()
t1 = time.perf_counter_ns()
print((t1 - t0) // 1000 // reqs)
PYEOF

run_cell() {   # run_cell <arm> <size>
    python3 "$WORK/drive.py" 127.0.0.1 "$PORT" "$1" "${BODY_BYTES[$2]}" "$REQS"
}

# Warm the page cache, the Go runtime and nginx's pools before timing.
for h in $ARMS; do
    for s in $SIZES; do run_cell "$h" "$s" >/dev/null; done
done
find "$WORK/body_temp" -type f -delete 2>/dev/null || true

declare -A SAMPLES
for ((r = 1; r <= ROUNDS; r++)); do
    # Interleaved, not arm-at-a-time: machine drift hits every arm equally.
    for s in $SIZES; do
        for h in $ARMS; do
            SAMPLES[$h,$s]="${SAMPLES[$h,$s]:-} $(run_cell "$h" "$s")"
        done
    done
    # in_file_only on keeps every spilled body; without this the sweep leaves
    # tens of GB behind and starts measuring the filesystem filling up.
    find "$WORK/body_temp" -type f -delete 2>/dev/null || true
    printf 'round %d/%d done\n' "$r" "$ROUNDS" >&2
done

kill -QUIT "$NGINX_PID" 2>/dev/null || true
wait "$NGINX_PID" 2>/dev/null || true

if grep -qE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log during the run"
    grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log"
    exit 1
fi

# $1 is a whitespace-separated sample list; the split is deliberate.
# shellcheck disable=SC2086
med() { printf '%s\n' $1 | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
spread() {
    # shellcheck disable=SC2086
    printf '%s\n' $1 | sort -n \
        | awk '{a[NR]=$1} END{m=a[int((NR+1)/2)];
                if (m == 0) print 0; else printf "%.1f", (a[NR]-a[1])*100.0/m}'
}

echo
echo "coraza-nginx forced-temp-file request-body latency"
echo "  nginx:  $NGINX"
echo "  rounds: $ROUNDS x $REQS requests/cell, concurrency 1, keepalive"
echo
printf '%-8s %9s %9s %9s %12s %12s %10s %9s\n' \
    size 'B' 'CMEM' 'CFILE' 'CFILE-CMEM' 'per-64K' 'CMEM-B' 'spread%'
worst=0
for s in $SIZES; do
    b=$(med "${SAMPLES[b,$s]}")
    m=$(med "${SAMPLES[cmem,$s]}")
    f=$(med "${SAMPLES[cfile,$s]}")
    chunks=$(( (${BODY_BYTES[$s]} + 65535) / 65536 ))
    read_cost=$(( f - m ))
    per=$(awk -v d="$read_cost" -v k="$chunks" 'BEGIN{printf "%.1f", d/k}')
    sp=$(spread "${SAMPLES[cfile,$s]}")
    awk -v w="$worst" -v x="$sp" 'BEGIN{exit !(x>w)}' && worst="$sp"
    printf '%-8s %9d %9d %9d %12d %12s %10d %9s\n' \
        "$s" "$b" "$m" "$f" "$read_cost" "$per" "$(( m - b ))" "$sp"
done
echo
echo "  Microseconds per request, median of $ROUNDS rounds."
echo "  B          connector on, body spilled to disk, never read back."
echo "  CMEM       same inspection, body kept in memory (read loop never runs)."
echo "  CFILE      same inspection, body on disk (read loop runs)."
echo "  CFILE-CMEM the synchronous read loop, and nothing else. This is the"
echo "             number the threading question turns on."
echo "  CMEM-B     libcoraza's own body processing -- unavoidable, and NOT"
echo "             removable by moving the read off the worker thread."
echo
echo "  Worst per-cell spread this run: ${worst}%."
echo "  A CFILE-CMEM under that spread times CFILE IS NOT A RESULT: if the"
echo "  read loop is small next to CMEM-B, the path is engine-dominated and"
echo "  threading the read cannot pay for its own complexity."
