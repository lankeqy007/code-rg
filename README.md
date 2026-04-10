# code-rg

Recovered source snapshot of the dan project, initialized from a local recovered workspace.

Current snapshot includes a minimal repair of the CPA upload chain:
- capture and persist OAuth/session tokens
- upload token JSON to the configured CPA endpoint with proper headers
- flush pending token uploads before program exit

Date: 2026-04-10
