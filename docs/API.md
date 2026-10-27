# Explorer API and MCP server

Explorer exposes its archive searches to programs: an MCP server at
`POST /mcp` for Fleet's agents (or any MCP host), and the same operations as
REST routes under `/api/v1/`. Both are thin adapters over one set of
functions (`internal/api`), so they cannot drift apart.

These are the search tools the agent bundles used to run in their Python
email server (`search_emails`, `search_emails_fuzzy`, `find_latest_report`).
They keep that contract: the same argument names, the same result fields and
warning codes, and the `s3_key` the bundles' remaining email tools
(`get_email`, `download_attachment`, `extract_download_links`,
`download_link_attachment`) take. Reading and downloading stay in the bundle;
Explorer only searches.

The web UI is unaffected: its own Search, Fuzzy and View modes keep their
behaviour, and none of the settings below apply to them.

## Tokens

Programs authenticate with a scoped bearer token, never with a browser
session. Mint one on the Explorer host:

```sh
explorer token create --label fleet-prod     # shown once; only its SHA-256 is stored
explorer token list                          # never shows secrets
explorer token revoke ID
```

Tokens start with `explorer_` and carry one scope, `email:search`: run the
three searches and read the metadata they return. A token cannot read a
message beyond the 500-character preview a search can return, download
attachments, change anything, or manage tokens or users. Tokens live in
`EXPLORER_API_TOKEN_DB` (default `/var/lib/explorer/api_tokens.db`, mode 0600,
owned by the service user; the CLI re-runs itself as that user). Explorer never
creates the database because of an unauthenticated request.

Send it as `Authorization: Bearer explorer_…`. A missing, unknown or revoked
token is a 401 with `WWW-Authenticate: Bearer realm="explorer"`. The browser's
sign-in cookie is not accepted here, and these routes never set one.

For Fleet, put the URL and token in its `.env`:

```sh
EXPLORER_MCP_URL=https://<this host>/mcp
EXPLORER_API_TOKEN=explorer_…
```

## MCP

`POST /mcp`: Streamable HTTP, stateless, plain `application/json` responses
(the same transport as Lens). One JSON-RPC message per POST; batches are
refused. Methods: `initialize`, `ping`, `tools/list`, `tools/call`.
Notifications get `202`. `GET`/`DELETE` are `405`: there is no SSE stream or
session. A browser `Origin` header must be this host (the request's or
`EXPLORER_PUBLIC_URL`'s); server-to-server callers send none.

Tools (all `readOnlyHint: true`; names, schemas and descriptions are in
`internal/mcp/tools.json`):

| Tool | Required | What it does |
|---|---|---|
| `search_emails` | `date_from`, `date_to` | Targeted search: `subject_contains`, `subject_keywords` (any), `sender_contains`, `recipient_contains`, `has_payload`, `max_results` (default 25, max 500), `include_body_preview`. Newest first. |
| `search_emails_fuzzy` | `keywords`, `date_from` | Keyword search over `search_fields` (`subject`, `sender`, `body`; default subject and sender), `match_all`, `max_results` (default 50). Ranked by `match_score`, then newest. `date_to` defaults to now. |
| `find_latest_report` | — | Walks back day by day from `on_or_before` (default today, UTC) for `lookback_days` (default 14, max 60) until `max_candidates` (default 1, max 25) matches. `require_payload` defaults to true. |

A tool result's text is the whole JSON body. Success bodies carry
`"ok": true, "status": "success"`; failures are `isError: true` results with
`"ok": false, "status": "error", "error", "code"` (and `"retryable": true`
where a retry may succeed).

### Results

Each email in `emails` has `s3_key`, `subject`, `from`, `to`, `date`,
`received_at` (S3 LastModified, ISO 8601), `size_bytes`,
`sender_authenticated`, `trusted_legacy_archive`, `payload_checked`,
`has_attachments`, `attachment_count` and `attachment_names`. Exact searches
add `has_download_links`, `download_link_count`, `download_links` (when
present: `url`, `filename`, `link_text`, `is_click_tracker`) and, when asked,
`body_preview`. Fuzzy searches add `match_score` and `matched_keywords`.

`payload_checked` is true when the whole message was read (`has_payload`, a
body preview, or a body search). Otherwise only the headers were read and the
attachment and link counts are 0 because they are unknown, not because the
message has none.

Every search also returns `matches_found`, `emails_scanned`, `search_stats`,
`search_criteria` (with the `effective_date_from`/`effective_date_to` used) and
`search_warnings`. `find_latest_report` returns `days_searched`,
`anchor_date`, `first_match_date`, `match_count`, `emails` and the days'
`search_warnings` merged per code with the `days` they came from.

### Sender authentication

A `From` header is text anyone can write. With `EMAIL_SENDER_AUTH=required`
(the default) the searches return only mail whose From domain the receiving
server authenticated. Explorer reads the topmost `Authentication-Results`
header carrying `EMAIL_AUTHSERV_ID` (default `amazonses.com`) and accepts:

- `dmarc=pass` for the From domain; or
- only when DMARC is absent or `dmarc=none`, `spf=pass` / `dkim=pass` for
  exactly that domain.

Any other DMARC result is final.

`sender_contains` items are a domain (`vendor.example`, which also matches its
subdomains) or a full mailbox (`reports@vendor.example`). They are matched
against the parsed From mailbox, never the display name. A bare word
(`exchange`) or a TLD matches nothing and draws `sender_filter_entries_ignored`.
In fuzzy searches that include `sender`, a domain- or address-shaped keyword
matches the sender only, and a plain word never matches a sender.

Unauthenticated mail is never opened. When it would have matched, it is
counted in a warning instead of being returned:

- `unauthenticated_sender_skipped` when the header filters alone decided the
  match;
- `unauthenticated_sender_unchecked` under `has_payload`, where whether it
  would match is unknown.

An agent must read those warnings before concluding that a vendor's report is
missing. `EMAIL_SENDER_AUTH=off` restores the forgeable header-text match for
an inbox whose receiver adds no `Authentication-Results`. Every search then
carries `unauthenticated_sender_match`.

`EMAIL_TRUSTED_LEGACY_PREFIXES` names S3 prefixes of imported legacy mail
that the operator vouches for. Their objects count as authenticated. Because
their LastModified is the import time, they are placed by their date
partition, or by their Date header outside the date tree.

### Payloads

`has_payload: true` asks for a MIME attachment or an in-body download link.
`false` asks for neither. Links come from HTML anchors and plain-text URLs.
Known wrappers (Proofpoint, Amazon Ads `CL0`, `awstrack`) are unwrapped first,
then a link is classified:

- **Download-likely:** a file extension, a download keyword or parameter, a
  presigned S3/GCS/Azure URL, or a click tracker.
- **Never a payload:** images, social and sign-in hosts, and unsubscribe
  links.

The classifier is a port of the bundles' `classify_url`; change both together.

### Date windows

Dates are ISO dates (`2026-06-01`) or datetimes; a datetime without an offset
is UTC. A date-only `date_to` runs to the end of that day. Searches read one S3
prefix per day of `EMAIL_S3_DATE_PREFIX_FORMAT`, newest day first. An object
listed under a day partition belongs to that day, whatever its LastModified.

Each day partition is scanned in full, then later days are skipped once
`max_results` is reached; legacy prefixes are always scanned.

| Window | Behaviour |
|---|---|
| Wider than 3 days | Served, with a `date_window_auto_chunked` warning. |
| Wider than `EMAIL_S3_MAX_DATE_PREFIX_DAYS` (default 62) | Refused. |
| Body search wider than `EMAIL_S3_MAX_BODY_SEARCH_DAYS` (default 14) | Refused. |

## REST

`POST /api/v1/<tool>` with a JSON object of the tool's arguments, for example:

```sh
curl -sS https://explorer.example/api/v1/find_latest_report \
  -H "Authorization: Bearer $EXPLORER_API_TOKEN" \
  -d '{"sender_contains": "vendor.example", "lookback_days": 7}'
```

The response is the tool's body with `"ok": true`, or the error body with its
HTTP status. `GET /api/v1/` lists the operations the token may call.

## Failure behaviour

A search either completes or fails; it never reports an empty success for an
archive it could not read.

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_argument`, `bounded_date_window_required`, `filter_not_meaningful` | 400 | Fix the arguments; `search_warnings` explains. |
| `unauthorized` / `forbidden` | 401 / 403 | Token missing, revoked or lacking the scope. |
| `archive_unavailable` | 502 | An S3 call failed (the S3 error code is named, e.g. `AccessDenied`). Retryable. Not "no email". |
| `timeout` | 504 | The call ran past `EXPLORER_API_MAX_SECONDS` (default 240) and was stopped. Narrow the query and retry. |
| `not_configured` | 503 | `EMAIL_S3_BUCKET` is unset. |
| `internal_error` | 500 | Logged on the host; no detail is returned. |

A day that fails during `find_latest_report` fails the whole call, with
`failed_day`, `days_searched` and the emails collected from the newer days
before it, so an older report never passes for the latest.

Only a message that cannot be read as mail is skipped and counted in
`search_stats.parse_errors`: an empty object (S3 `InvalidRange`, such as SES's
setup notification) or one over Explorer's download cap. Objects under
`EMAIL_S3_ARCHIVE_PREFIX` (the link-archive lambda's payloads and manifests)
are never returned as mail.

## What this does not do

- No message bodies, attachments or downloads beyond the bounded preview: the
  bundle's own email tools do that.
- No sending. Outbound mail stays with the bundles' `ses_sender`, so Explorer's
  AWS credentials stay read-only on the archive prefix.
- No token administration over the network: tokens are minted and revoked
  only on the host.
