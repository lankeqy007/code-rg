# code-rg

Recovered source snapshot of the dan project, initialized from a local recovered workspace.

Current snapshot includes a minimal repair of the CPA upload chain:
- capture and persist OAuth/session tokens
- upload token JSON to the configured CPA endpoint with proper headers
- flush pending token uploads before program exit
- add a lightweight `dan-web` control plane with `/api/status`, `/api/start`, `/api/stop`

Date: 2026-04-10

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/lankeqy007/code-rg/main/install.sh | bash -s -- \
  --install-dir "$HOME/dan-runtime" \
  --background \
  --cpa-base-url 'https://your-cpa.example/' \
  --cpa-token 'your-token' \
  --mail-api-url 'https://your-mail.example/' \
  --mail-api-key 'your-mail-key' \
  --threads 20 \
  --domains 'example.com'
```

## Status

```bash
curl -s -H "Authorization: Bearer linuxdo" http://127.0.0.1:25666/api/status
```

```bash
curl -s -X POST -H "Authorization: Bearer linuxdo" http://127.0.0.1:25666/api/start | jq
```

```bash
curl -s -X POST -H "Authorization: Bearer linuxdo" http://127.0.0.1:25666/api/stop | jq
```
