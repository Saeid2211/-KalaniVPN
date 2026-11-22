# KalaniVPN3 — Central Server Pool (phase 1)

This package adds an isolated GitHub Actions worker and a machine-readable pool. It does **not** modify Android app source files or the VPN connection lifecycle.

## What the worker does

1. Downloads candidates from the public feeds listed in `server-pool/sources.txt`.
2. Decodes plain and base64 subscription lists and accepts only supported URI schemes.
3. Converts each candidate with the pinned `unbox` v1.1.2 parser.
4. Validates the generated outbound with the official **sing-box 1.14.4** binary. The binary archive is SHA-256 checked before installation.
5. Starts one isolated sing-box instance with a local SOCKS5 inbound for each candidate.
6. Verifies the proxy exit country with two independent GeoIP endpoints. The source-feed country label is only a sampling hint and is never accepted as proof.
7. Sends two 1 MiB HTTPS downloads and one 256 KiB HTTPS upload through that SOCKS5 proxy. A candidate must complete every transfer and meet minimum throughput thresholds.
8. Publishes at most five verified nodes for each of US, DE, NL, GB and FR.

The pool is written to `server-pool/server-pool.json` and is available at:

`https://raw.githubusercontent.com/Saeid2211/-KalaniVPN/main/server-pool/server-pool.json`

## Install into the GitHub repository

Extract this package at the **root** of a separate clone of `Saeid2211/-KalaniVPN`, preserving the hidden `.github` directory. This package intentionally has no root `README.md`, so it will not overwrite the repository README. Do not copy it into the Android app source tree.

Then commit and push these additions:

```bash
git add .github/workflows/server-pool.yml server-pool/collect.py server-pool/sources.txt server-pool/README.md
git commit -m "Add independently verified Kalani server pool"
git push origin main
```

The workflow runs after this push, can also be started from **GitHub → Actions → Kalani server pool → Run workflow**, and is scheduled at minutes 17 and 47 of each hour. It uses a concurrency lock to prevent overlapping scans. It commits only the generated pool file, so that commit does not recursively trigger another scan.

## Important operating limits

- GitHub Actions is a scheduled worker, not an always-running VPS. Scheduled runs can be delayed. Public-repository scheduled workflows can be disabled after 60 days without repository activity; regular successful pool updates normally create activity, but this is not a service-level guarantee.
- The tests run from GitHub's hosted runner egress, not from every user's ISP. A node can pass centrally and still be blocked or slow on a particular user's mobile network. The Android app must later do a short local reachability check **only while the VPN is disconnected**.
- This worker is independent of the Android app. It cannot interrupt an active phone tunnel. The later app integration must preserve the existing invariant: once connected, do not scan, ping, refresh, or switch automatically.
- The pool contains credentials for public, third-party proxy nodes. Because this repository is public, those credentials are public too. Never add private, paid, personal or otherwise confidential server credentials. Public free nodes are not trusted infrastructure and should not be used for sensitive traffic.
- If a run finds no candidates that pass all checks, it leaves the last pool file untouched. The `generated_at` value is not refreshed, so clients can detect expiry rather than treating old data as newly verified.
- `server-pool.json` is a phase-1 data contract. Android app integration is intentionally separate and must be done against the actual local KalaniVPN3 source files, not the stale Android source files on this GitHub repository.

## Current acceptance thresholds

- Actual exit country: two GeoIP responses must agree and be one of US / DE / NL / GB / FR.
- Download: two complete 1 MiB HTTPS transfers, average at least 0.524 Mbps (512 Kibit/s).
- Upload: one complete 256 KiB HTTPS POST, at least 0.131 Mbps (128 Kibit/s).
- Ranking: throughput, upload, and time-to-first-byte; not raw TCP ping alone.
- Maximum output: five nodes per allowed country (25 total).
