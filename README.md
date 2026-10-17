# n8n-nodes-proofledger

An [n8n](https://n8n.io) community node for [ProofLedger](https://proofledger.io): anchor a file's SHA-256 hash on the Polygon blockchain from any workflow, read proofs back, and start workflows the moment a proof is anchored.

Only the hash is sent, plus a file name and External ID when the node has them (Create From File sends the binary's file name unless you set Filename). The file never leaves n8n.

## Install

In n8n: **Settings → Community Nodes → Install**, enter `n8n-nodes-proofledger`.

Self-hosted without the UI installer: `npm install n8n-nodes-proofledger` in your n8n user folder (`~/.n8n/nodes`), then restart n8n. The [n8n docs](https://docs.n8n.io/integrations/community-nodes/installation/) cover both paths.

## Credentials

One credential, **ProofLedger API**:

| Field | Value |
|---|---|
| API Key | Issued from **Account → API Keys** on any ProofLedger plan, including Free. Starts with `sk_` and is shown once. |
| Base URL | `https://proofledger.io`. Leave it. |

The credential test calls `GET /api/v1/branding`, which costs nothing and proves the key.

## ProofLedger node

| Resource | Operation | What it does |
|---|---|---|
| Proof | **Create From File** | Hashes a binary field locally with SHA-256 and submits the hash. Filename defaults to the binary's file name. |
| Proof | **Create From Hash** | Submits a 64-character SHA-256 hex digest you already have. |
| Proof | **Create Many** | Every incoming item's hash, in batches of 100, one request per batch. Output is one item per input (`result`: `created`, `exists` or `invalid`, plus the proof). |
| Proof | **Get** | Status, Polygon transaction and certificate links by proof ID. |
| Proof | **Get by External ID** | Look a proof up by the `external_id` you sent. |
| Proof | **Get Bundle** | Everything needed to verify the proof without ProofLedger, in the [verify-proof](https://pypi.org/project/verify-proof/) file format. |
| Proof | **Get Many** | Newest first; filter by *Anchored Since*; *Return All* pages through the cursor. |
| Proof | **Verify** | The public verify endpoint: does this hash have a proof? |
| Webhook | Create / Get Many / Delete / Test | Manage webhook endpoints by hand. The trigger node below does this for you. |
| Account | **Get Branding** | Whether partner branding is approved and the exact line shown on certificates. |

**External ID.** Send your own record ID on create (*Additional Fields → External ID*). Sending the same one again returns the existing proof instead of creating another, so retries are safe.

**Filename.** Stored with the proof. It appears on the public certificate and in your dashboard, so set Filename to something else if the real name is private.

**Errors.** Turn on *Continue On Fail* to get `{ "error": "..." }` items instead of a stopped workflow. A `429` means the key's 120 requests per minute is used up, or, on Free, its 100 API proofs a month (until the 1st of the next month, UTC); the message says which. Developer (1,000 a month) and Platform (10,000) do not stop at their allowance: each proof past it costs $0.01.

## Trigger

**ProofLedger Trigger** starts the workflow when a proof on your account is anchored on Polygon.

- On activation it registers a webhook endpoint at your n8n webhook URL (`POST /api/v1/webhooks`) and stores the signing secret in the workflow's static data. Deactivating removes the endpoint.
- Every delivery is checked against `ProofLedger-Signature` (`t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">`, 5-minute tolerance). Anything that fails is answered `401` and never starts the workflow.
- The item is the event body: `type`, `created_at`, and `data.proof` (status, `chain_tx`, certificate and verification URLs) plus `data.bundle` (the verify-proof bundle), so you can store the bundle next to the file without another call.
- **Include Test Events** also runs the workflow for the signed `webhook.test` event, which you can send from the ProofLedger account page or `POST /api/v1/webhooks/:id/test`.

Your n8n webhook URL must be reachable from the internet over **https**. ProofLedger refuses private, loopback and plain-http addresses.

## Templates

Two importable workflows in [`templates/`](templates/):

- `anchor-file-and-save-bundle.json`: read a file from disk → Create From File → wait for the anchor → Get Bundle → write `<file>.proof.json` next to it. Swap the first node for any node that produces a binary field (a form upload, Google Drive, S3, HTTP Request).
- `when-proof-anchored.json`: ProofLedger Trigger → one flat item per anchored proof (ID, hash, transaction, certificate link, bundle), ready for a database, an email or storage.

## Facts worth knowing

- One chain: every proof is one transaction on Polygon, usually confirmed within a minute. Plans and prices: https://proofledger.io/pricing.html.
- A proof shows that a file with this fingerprint existed by a date. It does not prove who made it and is not a copyright registration.
- Anyone can verify a proof without an account: the public verify page, the public verify endpoint, or the `verify-proof` package offline from the bundle.
- API reference: https://proofledger.io/api.html. Changelog: https://proofledger.io/changelog. Terms for API use: https://proofledger.io/api-terms.

## Development

```
npm install
npm run build      # compiles to dist/
npm run lint       # n8n's community-node rules
npm test           # signature verification unit tests (needs a build)
```

Releases after the first are published from GitHub Actions with npm provenance: `npm run release` lints, builds, bumps the version, tags and pushes, and `.github/workflows/publish.yml` publishes the tag. One-time setup on npmjs.com: package settings → Trusted Publishers → GitHub Actions, owner `Fulcrum-Enterprises`, repo `n8n-nodes-proofledger`, workflow `publish.yml`.

The package was proven against a real n8n 2.43 and a scratch ProofLedger instance: every operation above, trigger registration on activation, a forged and an unsigned delivery refused with 401, and a signed test event and a real anchored-proof event each starting an execution. The harness lives in `e2e/` and depends on a local ProofLedger checkout, so it is not part of `npm test`.

## License

MIT. ProofLedger is a product of ProofLedger LLC, which also maintains this node.
