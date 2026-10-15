# Security and privacy

HAR files can contain credentials, personal information and complete request/response bodies. Keep the original capture local. Do not attach it to a public issue just because a browser labels its export “sanitized.”

HAR Triage reads at most 16 MiB and analyzes at most 10,000 entries. It does not make network requests, execute HAR content, evaluate script, or change the source capture. The runtime analysis/report/CLI modules have no third-party dependencies. The Harness adapter uses the host's tools, filesystem and sandbox services.

## Output policy

Only explicitly selected numeric fields, controlled method/content/status classes, endpoint aliases and fixed findings enter reports. No raw URL, hostname, path, query value, header, cookie, body, page title, source IP, initiator, extension field, absolute timestamp or original-file digest is retained. Parse errors use fixed messages rather than JSON parser excerpts.

The original zero-based entry index lets you look up a request in the private source capture. No separate URL mapping is written. The HTML embeds only this projection, escapes its JSON and uses a restrictive content policy; it does not load external assets or contact a service. Its clipboard control copies only `log.entries[N]`, with a visible fallback when clipboard access is unavailable.

This policy reduces disclosure; it cannot prove that retained timings, sizes, counts, response patterns and endpoint grouping are not identifying. Review JSON and HTML before sharing. Do not describe a generated report as guaranteed anonymous or a completely sanitized HAR.

## Filesystem behavior

Harness operations are confined to its resolved session workspace using the host filesystem service and current sandbox policy. Static symlinks outside the workspace are refused. This does not claim protection beyond the host filesystem contract against a separate malicious process racing directory replacement.

Reports use exclusive creation rather than replacing files. An interrupted two-file publication can retain the completed JSON without the HTML. The standalone CLI creates a new private directory and private report files on POSIX systems; Windows ACLs remain an operating-system concern.

## Reporting

For a suspected vulnerability, contact the repository owner through a private channel advertised on the GitHub profile. Do not send real captures, tokens or personal traffic in a public issue. A synthetic minimal reproducer is preferred.
