#!/usr/bin/env python3
"""
cert_history.py - Point-and-shoot TLS certificate / CT-log recon for
threat intel work. Pulls cert history from crt.sh (with retry/backoff
for its constant 503s) and falls back to CertSpotter automatically.

Single target:
    python3 cert_history.py example.com
    python3 cert_history.py example.com --wildcard --json out.json
    python3 cert_history.py example.com --subdomains
    python3 cert_history.py example.com --csv out.csv

Batch (one domain per line, blank lines / #comments ignored):
    python3 cert_history.py -f targets.txt --subdomains --out-dir ./recon
"""

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

DEFAULT_HEADERS = {
    "User-Agent": "cert-history-script/1.1 (+research tool)"
}


def query_crtsh(domain: str, wildcard: bool = False, max_retries: int = 3,
                 base_delay: float = 2.0, timeout: int = 30):
    """
    Query crt.sh's JSON endpoint. crt.sh's backend is notoriously
    overloaded, so 503/504/timeouts are routine. Retry with
    exponential backoff instead of failing on the first bad response.
    """
    q = f"%.{domain}" if wildcard else domain
    params = {"q": q, "output": "json"}

    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(
                CRTSH_URL, params=params, headers=DEFAULT_HEADERS, timeout=timeout
            )
            if resp.status_code == 200:
                try:
                    return resp.json()
                except json.JSONDecodeError as e:
                    last_err = f"bad JSON body: {e}"
            else:
                last_err = f"HTTP {resp.status_code}"
        except requests.RequestException as e:
            last_err = str(e)

        if attempt < max_retries:
            delay = base_delay * (2 ** (attempt - 1))
            print(f"    [crt.sh] attempt {attempt} failed ({last_err}); "
                  f"retrying in {delay:.1f}s...", file=sys.stderr)
            time.sleep(delay)

    print(f"    [crt.sh] giving up after {max_retries} attempts: {last_err}",
          file=sys.stderr)
    return None


def query_certspotter(domain: str, include_subdomains: bool = True, timeout: int = 30):
    """
    Fallback source: CertSpotter free tier, no key needed at low volume.
    NOTE: CertSpotter's API only ever returns unexpired issuances - there is
    no parameter to include expired certs. So this fallback gives you what's
    currently valid, not full history the way crt.sh does. Treat it as a
    "what's live right now" check when crt.sh is down, not a full replacement.

    CertSpotter also caps each response to a limited page size and expects
    you to page forward with the `after` cursor (the last issuance's `id`)
    until an empty response comes back. This walks every page so the result
    isn't silently truncated at the first page.
    """
    all_records = []
    after = None
    page = 0

    while True:
        page += 1
        params = [
            ("domain", domain),
            ("include_subdomains", str(include_subdomains).lower()),
            ("expand", "dns_names"),
            ("expand", "issuer"),
        ]
        if after:
            params.append(("after", after))

        try:
            resp = requests.get(
                CERTSPOTTER_URL, params=params, headers=DEFAULT_HEADERS, timeout=timeout
            )
        except requests.RequestException as e:
            print(f"    [certspotter] request failed on page {page}: {e}", file=sys.stderr)
            break

        if resp.status_code != 200:
            print(f"    [certspotter] HTTP {resp.status_code} on page {page}: {resp.text[:200]}",
                  file=sys.stderr)
            break

        try:
            batch = resp.json()
        except json.JSONDecodeError as e:
            print(f"    [certspotter] bad JSON on page {page}: {e}", file=sys.stderr)
            break

        if not batch:
            break  # empty page = done

        all_records.extend(batch)
        after = batch[-1].get("id")
        if not after:
            break

    return all_records if all_records else None


def normalize_crtsh(records):
    out = []
    for r in records:
        out.append({
            "source": "crt.sh",
            "id": r.get("id"),
            "issuer": r.get("issuer_name"),
            "common_name": r.get("common_name"),
            "name_value": r.get("name_value"),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
        })
    return out


def normalize_certspotter(records):
    out = []
    for r in records:
        out.append({
            "source": "certspotter",
            "id": r.get("id"),
            "issuer": (r.get("issuer") or {}).get("name"),
            "common_name": None,
            "name_value": "\n".join(r.get("dns_names") or []),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
        })
    return out


def sort_key(r):
    try:
        return datetime.fromisoformat((r.get("not_before") or "").replace("Z", "+00:00"))
    except Exception:
        return datetime.min


def extract_subdomains(records, root_domain):
    names = set()
    for r in records:
        raw = r.get("name_value") or ""
        for n in raw.split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and root_domain.lower() in n:
                names.add(n)
    return sorted(names)


def process_domain(domain, args):
    print(f"[*] {domain}: querying crt.sh ...", file=sys.stderr)
    crtsh_raw = query_crtsh(domain, wildcard=args.wildcard)

    combined = []
    if crtsh_raw:
        combined.extend(normalize_crtsh(crtsh_raw))
        print(f"[+] {domain}: crt.sh returned {len(crtsh_raw)} records", file=sys.stderr)
    else:
        print(f"[-] {domain}: crt.sh failed", file=sys.stderr)

    if (not crtsh_raw) and not args.no_fallback:
        print(f"[*] {domain}: falling back to CertSpotter ...", file=sys.stderr)
        cs_raw = query_certspotter(domain)
        if cs_raw:
            combined.extend(normalize_certspotter(cs_raw))
            print(f"[+] {domain}: CertSpotter returned {len(cs_raw)} records", file=sys.stderr)
        else:
            print(f"[-] {domain}: CertSpotter also failed", file=sys.stderr)

    combined.sort(key=sort_key, reverse=True)
    for r in combined:
        r["domain"] = domain
    return combined


def next_available_path(base: str, extension: str = "") -> Path:
    """
    Return base+extension if nothing exists there yet, otherwise
    base_2+extension, base_3+extension, etc. - first free slot wins.
    Used for the default output name/dir so each run gets its own file
    rather than overwriting or merging into a previous run's results.
    """
    candidate = Path(f"{base}{extension}")
    if not candidate.exists():
        return candidate
    n = 2
    while True:
        candidate = Path(f"{base}_{n}{extension}")
        if not candidate.exists():
            return candidate
        n += 1


def write_json(records, path):
    with open(path, "w") as f:
        json.dump(records, f, indent=2, default=str)


def write_csv(records, path):
    fields = ["domain", "source", "id", "issuer", "common_name", "name_value", "not_before", "not_after"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k) for k in fields})


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("domain", nargs="?", help="Single domain to look up (e.g. example.com)")
    target.add_argument("-f", "--file", help="File with one domain per line for batch mode")

    ap.add_argument("--wildcard", action="store_true",
                     help="Search %%.domain instead of exact domain (crt.sh only)")
    ap.add_argument("--subdomains", action="store_true",
                     help="Print/write unique subdomains seen in cert SANs instead of full records")
    ap.add_argument("--json", metavar="FILE",
                     help="Write raw combined results to FILE (single-domain mode). "
                          "Default: auto-numbered 'TLS cert results.json', 'TLS cert results_2.json', ...")
    ap.add_argument("--csv", metavar="FILE", help="Write raw combined results to FILE as CSV (single-domain mode)")
    ap.add_argument("--out-dir", metavar="DIR",
                     help="Batch mode: write one <domain>.json (or .txt if --subdomains) per target here. "
                          "Default: auto-numbered 'TLS cert results/', 'TLS cert results_2/', ...")
    ap.add_argument("--no-save", action="store_true",
                     help="Don't write any output file; print to stdout/stderr only")
    ap.add_argument("--no-fallback", action="store_true",
                     help="Don't fall back to CertSpotter if crt.sh fails")
    args = ap.parse_args()

    domains = []
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
        if not args.no_save:
            out_dir = Path(args.out_dir) if args.out_dir else next_available_path("TLS cert results")
            out_dir.mkdir(parents=True, exist_ok=True)
            args.out_dir = str(out_dir)
    else:
        domains = [args.domain]
        if not args.no_save and not args.json and not args.csv:
            args.json = str(next_available_path("TLS cert results", ".json"))

    any_data = False
    for domain in domains:
        records = process_domain(domain, args)
        if not records:
            print(f"[!] {domain}: no data from any source.\n", file=sys.stderr)
            continue
        any_data = True

        if args.subdomains:
            subs = extract_subdomains(records, domain)
            print(f"\n--- {domain}: {len(subs)} unique subdomains ---")
            for s in subs:
                print(s)
            if args.out_dir:
                (Path(args.out_dir) / f"{domain}.txt").write_text("\n".join(subs) + "\n")
        else:
            print(f"\n--- {domain}: {len(records)} cert records ---")
            for r in records:
                name = r.get("common_name") or r.get("name_value")
                print(f"[{r['source']}] {r.get('not_before')} -> {r.get('not_after')} "
                      f"| issuer={r.get('issuer')} | name={name}")
            if args.out_dir:
                write_json(records, Path(args.out_dir) / f"{domain}.json")

        if not args.file:
            if args.json:
                write_json(records, args.json)
                print(f"\n[+] Wrote {len(records)} records to {args.json}", file=sys.stderr)
            if args.csv:
                write_csv(records, args.csv)
                print(f"[+] Wrote {len(records)} records to {args.csv}", file=sys.stderr)
        print("", file=sys.stderr)

    if not any_data:
        sys.exit(1)


if __name__ == "__main__":
    main()
