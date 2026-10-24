#!/usr/bin/env python3
"""Daily Chromium / Termux upstream watcher; never builds or promotes."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

RELEASES = ('https://chromiumdash.appspot.com/fetch_releases'
            '?channel=Stable&platform=Linux&num=10&offset=0')
TERMUX = 'termux/termux-packages'
HOST_PATH = 'x11-packages/chromium-host-tools/build.sh'
RECIPE_PATH = 'x11-packages/chromium/build.sh'
NUMERIC = re.compile(r'^[0-9]+(?:\.[0-9]+){3}$')
VERSION = re.compile(r"""^\s*TERMUX_PKG_VERSION\s*=\s*['"]?([0-9]+(?:\.[0-9]+){3})['"]?\s*(?:#.*)?$""", re.M)


def version_parts(s: str) -> tuple[int, ...]:
    if not NUMERIC.fullmatch(s):
        raise ValueError(f'Unexpected Chromium version: {s!r}')
    return tuple(int(x) for x in s.split('.'))


def extract_version(text: str, path: str) -> str:
    match = VERSION.search(text)
    if not match:
        raise ValueError(f'Unable to read literal TERMUX_PKG_VERSION from {path}')
    return match.group(1)


def fetch(url: str, token: str | None = None) -> bytes:
    headers = {'User-Agent': 'termux-chromium-sandbox-upstream-check',
               'Accept': 'application/vnd.github+json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                timeout=25) as response:
        return response.read()


def get_json(url: str, token: str | None = None):
    return json.loads(fetch(url, token))


def latest_stable(items) -> str:
    versions = [v for x in items if isinstance(x, dict)
                if (v := x.get('version', '')) and NUMERIC.fullmatch(v)]
    if not versions:
        raise ValueError('No Chromium Linux Stable version in ChromiumDash API')
    return max(versions, key=version_parts)


def termux_snapshot(token: str | None) -> tuple[str, str, str]:
    sha = get_json(f'https://api.github.com/repos/{TERMUX}/commits/master',
                   token)['sha']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Invalid immutable Termux source SHA')
    versions = []
    for path in (HOST_PATH, RECIPE_PATH):
        url = f'https://raw.githubusercontent.com/{TERMUX}/{sha}/{path}'
        versions.append(extract_version(fetch(url).decode('utf-8'), path))
    return sha, versions[0], versions[1]


def find_existing_issue(repo: str, title: str, token: str):
    # Exact-title dedupe, across open AND closed issues.
    for page in range(1, 101):
        url = (f'https://api.github.com/repos/{repo}/issues'
               f'?state=all&per_page=100&page={page}')
        entries = get_json(url, token)
        for issue in entries:
            if 'pull_request' not in issue and issue.get('title') == title:
                return issue
        if len(entries) < 100:
            return None
    raise RuntimeError('Issue history too long to deduplicate safely')


def create_issue(repo: str, title: str, body: str, token: str):
    request = urllib.request.Request(
        f'https://api.github.com/repos/{repo}/issues',
        data=json.dumps({'title': title, 'body': body}).encode('utf-8'),
        method='POST',
        headers={'User-Agent': 'termux-chromium-sandbox-upstream-check',
                 'Accept': 'application/vnd.github+json',
                 'Content-Type': 'application/json',
                 'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def issue_body(baseline: str, stable: str, host: str,
               recipe: str, sha: str) -> str:
    return f"""## Chromium update candidate

Automatically detected by the daily upstream watcher.
**This is an informational issue, not authorization to build or publish.**

| Source | Version |
| --- | --- |
| Validated chromium-sandboxed | {baseline} |
| Chromium upstream Linux Stable | {stable} |
| Termux chromium-host-tools/build.sh | {host} |
| Termux chromium/build.sh | {recipe} |

- Pinned Termux commit: https://github.com/{TERMUX}/commit/{sha}
- Host-tools source: https://github.com/{TERMUX}/blob/{sha}/{HOST_PATH}
- Chromium recipe: https://github.com/{TERMUX}/blob/{sha}/{RECIPE_PATH}
- Chrome Linux Stable: {RELEASES}

**Chrome Stable publication does not imply Termux recipe readiness.**
Host-tools and the Chromium recipe may temporarily have different versions.

### Human approval gates
- [ ] Review Chromium and both Termux recipe changes.
- [ ] Check that the versions are aligned; pin exact Termux commit.
- [ ] Run fail-closed R1–R9b transformer and recipe tests, including forbidden patch guards.
- [ ] Obtain approval for a candidate CI build; never use mutable master.
- [ ] Verify DEB SHA256, package identity, BPF / no-new-privs, both-device A/B/C/D regressions.
- [ ] Obtain separate approval for validated promotion and any release.

**No automatic build, merge, promotion, feature-default change, Release or apt publication.**
Network and Audio service sandboxes retain upstream Linux default-OFF.
"""


def report(lines: list[str]) -> None:
    output = '\n'.join(lines) + '\n'
    print(output)
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--ledger', type=Path, default=Path('port/port.toml'))
    args = parser.parse_args()
    with args.ledger.open('rb') as stream:
        baseline = tomllib.load(stream)['port']['last_validated_chromium']
    version_parts(baseline)
    token = os.environ.get('GH_TOKEN')
    stable = latest_stable(get_json(RELEASES))
    sha, host, recipe = termux_snapshot(token)
    candidate = max((stable, host, recipe), key=version_parts)
    lines = [
        '## Daily Chromium upstream check', '',
        f'- Validated: {baseline}',
        f'- Linux Stable: {stable}',
        f'- Termux host-tools: {host}',
        f'- Termux chromium recipe: {recipe}',
        f'- Termux pinned source SHA: {sha}'
    ]

    if version_parts(candidate) <= version_parts(baseline):
        report(lines + ['', 'No newer Chromium candidate. No changes.'])
        return 0

    title = f'Chromium upstream update: {candidate}'
    if args.dry_run:
        report(lines + ['', f'DRY RUN: would check/create GitHub issue: {title}'])
        return 0

    repo = os.environ.get('GITHUB_REPOSITORY', '')
    if not token or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise RuntimeError('No valid GH_TOKEN / GITHUB_REPOSITORY: refusing write')
    existing = find_existing_issue(repo, title, token)
    if existing:
        report(lines + ['', f'Existing issue #{existing["number"]}: no duplicate'])
        return 0
    created = create_issue(repo, title, issue_body(baseline, stable, host, recipe, sha),
                           token)
    report(lines + ['', f'New update issue #{created["number"]}: {created["html_url"]}'])
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, urllib.error.URLError, RuntimeError) as exc:
        print(f'FAIL CLOSED: {exc}', file=sys.stderr)
        sys.exit(1)
