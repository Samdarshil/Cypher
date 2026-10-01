# Deployment and evidence storage

## Local use

`cypher serve` binds to `127.0.0.1:8765` by default and stores investigations under `./cases`. Local browser use needs no access token. Evidence originals are copied into each case's `evidence/` directory and hashed after the copy; analysis uses those managed copies. The original file is not executed or automatically extracted.

## Render backend

The repository does not include a Render service or persistent-disk manifest. For a durable single-instance deployment, attach a Render persistent disk and set the case directory to a path on its mount. Configure:

- Start command: `cypher serve --host 0.0.0.0 --port $PORT --cases-dir /var/data/cypher/cases`
- Disk mount path: `/var/data`
- `CYPHER_ACCESS_TOKEN`: a long random secret shared with the intended analyst(s)
- `CYPHER_PUBLIC_DEMO`: optional; defaults to `false`. Set to the exact value `true` to allow the Vercel frontend to access the API without a token.
- `CYPHER_MAX_UPLOAD_BYTES`: optional integer from 1 through 104857600; defaults to 20971520 (20 MiB)

By default, the process refuses a non-local bind without `CYPHER_ACCESS_TOKEN`. The token protects API routes and uploads; the browser asks for it at page load and keeps it in memory for that tab. This is a shared bearer token, not per-user authentication, authorization by investigation, or an enterprise identity system.

For a public demo, set `CYPHER_PUBLIC_DEMO=true` in the Render service environment. This explicitly disables token authentication for all API routes, and anyone can create, read, or change demo investigations. The frontend checks a public configuration response and skips the token prompt. The server-local-path evidence route is rejected in this mode; browser uploads remain subject to `CYPHER_MAX_UPLOAD_BYTES`. Use demo data only. The public configuration response contains only the boolean `public_demo` value; it does not return environment variables, credentials, or server paths. If the variable is unset or has any value other than `true`, the existing token behavior remains in effect.

Render's ephemeral filesystem is not a durable evidence store. Without the mounted disk, case records and evidence may be lost on restart or replacement. This implementation uses the existing per-case filesystem layout so the analysis engine can read evidence in place; it does not integrate an object-store backend. Keep the disk mounted at the same path across deploys and back it up. A single persistent volume also means this deployment is one writable instance; do not scale multiple server instances against local disk.

## Vercel frontend

Set the Vercel project root directory to `frontend`. `frontend/vercel.json` proxies investigation API calls to `https://cypher-api.onrender.com`, the Render origin associated with this Cypher project. Confirm that this is still the active backend before deploying; if the Render service URL changed, update the three rewrite destinations. The token travels in an HTTPS Authorization header through the rewrite. No secret is stored in frontend source or Vercel configuration.

Vercel serves the static frontend separately; uploaded bytes pass through the Vercel rewrite to Render and remain subject to the configured per-file cap. The API accepts one file per multipart request; the UI uploads a multi-file selection sequentially and reports each result, including partial success.

## Upload contract and limits

- `POST /investigations/{case_id}/evidence/upload`
- `Content-Type: multipart/form-data` with one `file` part
- `Authorization: Bearer <CYPHER_ACCESS_TOKEN>` on private deployments; omitted in public demo mode
- Success: `201` and the standard evidence metadata (`evidence_id`, original filename, byte size, server SHA-256, detected MIME hint, ingestion time and state)
- Errors: `400` invalid request, `403` missing/invalid access token, `404` unknown investigation, `413` configured request/file limit exceeded
- Default individual file limit: 20 MiB; maximum configurable limit: 100 MiB
- Exactly one file per request; filename is limited to 255 characters

Uploads are bounded by the configured request limit (file limit plus 256 KiB of multipart framing). The multipart parser temporarily retains both the raw request and decoded file bytes, so budget roughly twice the file limit in peak memory. Data is staged inside the investigation evidence directory, copied through the existing evidence registry, and cleaned up on success or failure. The registry removes a copied original if metadata persistence fails and replaces inventory metadata atomically. SHA-256 is calculated from the server's stored bytes. Metadata provides provenance, but Cypher does not claim a complete legal chain of custody, tamper-evident audit log, or immutable filesystem enforcement.

The UI labels MIME as a detected hint; it is not proof of file type. All uploaded content remains untrusted. Upload does not execute or extract files. Existing analysis tools and their sandbox policies remain responsible for safe processing.
