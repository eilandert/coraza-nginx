# Location policy contracts

Transactions bind to the enabled location that reaches PREACCESS after nginx
finishes ordinary location-rematching rewrites. Early responses such as rewrite
`return` bind in the response header filter when they skip PREACCESS. The final
location supplies the effective WAF and the transaction-ID expression. Request
metadata continues to use the original request URI.

Headerless exits such as `return 444` collect request facts in LOG using the
settled policy. This audit-only path records nginx's completed status in Coraza
and never applies interventions or changes the completed response. Failed
initialization remains bounded; a later LOG call may retry a missing context,
while an existing transaction is logged and freed once.

A retained context owns one transaction and processes request headers once.
True internal and named redirects clear nginx's module contexts; an enabled
destination creates a separate transaction. Each context keeps its existing
pool cleanup and response-header one-shot guard.

Run `bash ci/location-policy-build.sh` to verify pinned archives, generate the
upstream libcoraza header, build the dynamic module, and run the contracts.
Alternatively, with configured nginx and libcoraza headers available:

```sh
TEST_NGINX_SOURCE=/path/to/nginx \
TEST_LIBCORAZA_INCLUDE=/path/to/include \
    prove -v ci/location-policy-contract.t
```

The executable compiles the actual request-header, PREACCESS, response-header,
logging and utility functions, plus the extracted constructor and cleanup,
against real nginx/libcoraza headers. WAFs and transactions are inert integer
handles. The fixture supplies nginx allocation and continuation callbacks;
unsupported operations fail explicitly. No nginx server or rule engine runs.
The two phase-registration assertions are source-contract lint. Simulated
location changes test connector ownership, not nginx's rewrite implementation.

Cases cover different and shared WAF handles, main-WAF fallback, final configured
IDs, enabled/disabled transitions, early responses and failures, retained-context
resumes, internal redirects, independent subrequests, and log/free counters.
Response-header reentry and initialization errors must remain bounded. The
headerless-exit controls check ordinary, error and interrupted engine results
without any transport activity or modification of completed response state. The
constructor cleanup-registration failure case only checks the header caller's
handling of an unusable result; it does not change constructor publication or
claim a constructor fix.
