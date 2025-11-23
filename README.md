# api-hunter (scaffold)

Minimal scaffold for the API-focused recon scanner described in project notes.

Build (release):

```powershell
cd D:\Programmieren\Projekte\API_Hunter
cargo build --release
```

Run example (this writes `target_raw.jsonl`, `target_apis_sorted.csv`, `target_top.txt`):

```powershell
cargo run --release -- proton.me --out .\results\proton
```

Packaging for Kali:

- Build `cargo build --release` and copy `target\release\api_hunter` to `/usr/local/bin/api-hunter` on Kali.
- For a Debian package, use `cargo deb` or build a simple `.deb` wrapper (not included in scaffold).

Next steps to implement:
- discovery/gather modules (crt.sh, gau, wayback) as streaming producers
- probe (reqwest async HEAD->GET fallback, per-host throttling)
- enrich (json-shape detection, graphQL heuristics)
- scoring and CLI flags `--aggressive`, `--resume` etc.
