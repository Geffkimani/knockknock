#!/usr/bin/env python3
"""
KnockKnock — a polite, non-intrusive path scanner.

USAGE (example):
  python3 knockknock.py --targets targets.txt --output findings.txt --concurrency 5 --respect-robots --confirm-scope

IMPORTANT: Only run this against targets you are authorized to test.
"""

import argparse
import concurrent.futures
import logging
import requests
import time
from urllib.parse import urljoin, urlparse
from pathlib import Path

# Default "interesting" paths (kept small and generic), you can add more
DEFAULT_TARGET_PATHS = [
    '/.env',
    '/phpinfo.php',
    '/backup.zip',
    '/.git/',
    '/api/test',
    '/admin/',
    '/aws-s3-bucket-config.json'
]

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def parse_args():
    p = argparse.ArgumentParser(description="KnockKnock — polite, non-intrusive scanner (use responsibly).")
    p.add_argument('--targets', '-t', required=True, help='File with one base URL per line (e.g. https://example.com)')
    p.add_argument('--paths', '-p', nargs='*', default=DEFAULT_TARGET_PATHS, help='Paths to check (overrides defaults)')
    p.add_argument('--output', '-o', default='initial_findings.txt', help='File to write findings')
    p.add_argument('--concurrency', '-c', type=int, default=5, help='Number of worker threads (lower is more polite)')
    p.add_argument('--delay', type=float, default=0.5, help='Delay (seconds) between requests to the same target (politeness)')
    p.add_argument('--respect-robots', action='store_true', help='Respect robots.txt disallow rules (best-effort)')
    p.add_argument('--dry-run', action='store_true', help='Parse targets and show what would be scanned, do not perform requests')
    p.add_argument('--confirm-scope', action='store_true', help='Require confirmation that you have permission to scan targets')
    p.add_argument('--user-agent', default='KnockKnock/1.0 (Security Research — Authorized Only)', help='User-Agent header')
    return p.parse_args()

def load_targets(path):
    data = Path(path).read_text().splitlines()
    targets = [line.strip() for line in data if line.strip() and not line.strip().startswith('#')]
    # ensure trailing slash or consistent base
    normalized = []
    for t in targets:
        if not t.lower().startswith(('http://', 'https://')):
            t = 'https://' + t  # prefer https; user can supply http explicitly if needed
        normalized.append(t.rstrip('/'))
    return normalized

def fetch_robots(session, base_url, timeout=5):
    try:
        robots_url = urljoin(base_url + '/', 'robots.txt')
        r = session.get(robots_url, timeout=timeout, allow_redirects=True)
        if r.status_code == 200:
            return r.text
    except requests.RequestException:
        pass
    return ''

def disallowed_paths_from_robots(robots_txt, user_agent='*'):
    """
    Very small, best-effort robots.txt parser: returns a set of Disallow paths for the given UA.
    Not a full parser — used only to avoid obviously disallowed paths when respect-robots is enabled.
    """
    disallowed = set()
    current_ua = None
    for line in robots_txt.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue
        k, v = parts[0].strip().lower(), parts[1].strip()
        if k == 'user-agent':
            current_ua = v
        elif k == 'disallow' and current_ua is not None:
            # If the robots file has multiple groups, this keeps it simple:
            if current_ua == '*' or user_agent.lower() in current_ua.lower():
                disallowed.add(v)
    return disallowed

def is_allowed_by_robots(path, disallowed_set):
    # path is like "/admin/". We check simple prefix matches.
    for d in disallowed_set:
        if not d:
            continue
        if path.startswith(d):
            return False
    return True

def knock_knock(base_url, paths, session, delay, timeout, user_agent, respect_robots=False, disallowed_set=None):
    findings = []
    headers = {'User-Agent': user_agent}

    # polite per-target pacing
    for path in paths:
        if respect_robots and disallowed_set is not None:
            if not is_allowed_by_robots(path, disallowed_set):
                logging.debug("Skipping %s%s due to robots.txt disallow", base_url, path)
                continue
        target_url = urljoin(base_url + '/', path.lstrip('/'))
        try:
            r = session.get(target_url, timeout=timeout, headers=headers, allow_redirects=True, verify=True)
            if r.status_code == 200 and len(r.text or '') > 10 and "Page Not Found" not in r.text:
                # keep the logging non-sensitive
                findings.append({
                    'url': target_url,
                    'status': r.status_code,
                    'length': len(r.text)
                })
            # polite delay between requests to the same host
            time.sleep(delay)
        except requests.RequestException as e:
            logging.debug("Request failed for %s: %s", target_url, e)
    return findings

def main():
    args = parse_args()

    if args.confirm_scope:
        # require explicit confirmation for scanning
        confirm = input("Do you confirm you HAVE AUTHORIZATION to scan these targets? Type 'yes' to continue: ").strip().lower()
        if confirm != 'yes':
            logging.error("Confirmation not received. Exiting.")
            return

    targets = load_targets(args.targets)
    if not targets:
        logging.error("No targets loaded from %s", args.targets)
        return

    logging.info("Targets loaded: %d", len(targets))
    if args.dry_run:
        logging.info("Dry run mode. The following targets would be scanned:")
        for t in targets:
            logging.info("  - %s", t)
        return

    session = requests.Session()
    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_to_target = {}
        for base in targets:
            # gather robots info if requested
            disallowed_set = set()
            if args.respect_robots:
                robots_txt = fetch_robots(session, base)
                if robots_txt:
                    disallowed_set = disallowed_paths_from_robots(robots_txt, user_agent=args.user_agent)
            # schedule job
            future = executor.submit(
                knock_knock,
                base,
                args.paths,
                session,
                args.delay,
                5,  # request timeout
                args.user_agent,
                args.respect_robots,
                disallowed_set
            )
            future_to_target[future] = base

        for fut in concurrent.futures.as_completed(future_to_target):
            base = future_to_target[fut]
            try:
                findings = fut.result()
                for f in findings:
                    line = f"[FOUND] {f['url']} - Status: {f['status']} - Length: {f['length']}"
                    logging.info(line)
                    all_findings.append(line)
            except Exception as e:
                logging.error("Error scanning %s: %s", base, e)

    # Save results
    out_path = Path(args.output)
    out_path.write_text('\n'.join(all_findings) + ('\n' if all_findings else ''))
    logging.info("Scan complete. Found %d potential leads. Results saved to %s", len(all_findings), out_path)

if __name__ == '__main__':
    main()
