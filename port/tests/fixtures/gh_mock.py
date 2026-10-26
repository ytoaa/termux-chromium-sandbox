#!/usr/bin/env python3
"""Stateful mock of the `gh` release surface for publisher tests.

Store: $GH_MOCK_STORE/releases.json (+ asset blobs under store/files/).
Failure injection (env): GH_MOCK_FAIL_PHASE=create|upload|edit|view,
GH_MOCK_FAIL_ASSET=<name> (fail that upload), GH_MOCK_TAMPER_ASSET=<name>
(serve modified bytes on download), GH_MOCK_FAIL_MSG=<text>.
Only the commands port/publish_release.py uses are implemented.
"""
import json, os, sys, shutil
from pathlib import Path

STORE = Path(os.environ['GH_MOCK_STORE'])
REL = STORE / 'releases.json'
FILES = STORE / 'files'
FILES.mkdir(parents=True, exist_ok=True)

def load():
    return json.loads(REL.read_text()) if REL.is_file() else {}
def save(d):
    REL.write_text(json.dumps(d))
def fail(msg, code=1):
    print(msg, file=sys.stderr); sys.exit(code)
def phase(p):
    if os.environ.get('GH_MOCK_FAIL_PHASE') == p:
        fail(os.environ.get('GH_MOCK_FAIL_MSG', f'mock api error in {p}'))

argv = sys.argv[1:]
if argv[:2] == ['release', 'create']:
    phase('create')
    tag = argv[2]; d = load()
    if tag in d:
        fail(f'gh: release tag {tag} already exists')
    notes = ''
    if '--notes-file' in argv:
        notes = Path(argv[argv.index('--notes-file') + 1]).read_text()
    title = argv[argv.index('--title') + 1] if '--title' in argv else tag
    target = argv[argv.index('--target') + 1] if '--target' in argv else ''
    d[tag] = {'tag_name': tag, 'draft': '--draft' in argv,
              'prerelease': '--prerelease' in argv, 'target': target,
              'title': title, 'body': notes, 'assets': [],
              'html_url': f'https://github.com/r/p/releases/tag/{tag}'}
    save(d); sys.exit(0)
if argv[:2] == ['release', 'upload']:
    tag = argv[2]; d = load()
    if tag not in d: fail('Not Found')
    src = next(a for a in argv[3:] if not a.startswith('--'))
    name = os.path.basename(src)
    if os.environ.get('GH_MOCK_FAIL_ASSET') == name:
        fail(os.environ.get('GH_MOCK_FAIL_MSG', f'mock upload error for {name}'))
    phase('upload')
    if any(a['name'] == name for a in d[tag]['assets']):
        fail(f'gh: asset {name} already exists')
    dst = FILES / f'{tag}-{name}'
    shutil.copy2(src, dst)
    d[tag]['assets'].append({'name': name, 'path': str(dst),
                             'url': f'https://example.invalid/assets/{name}'})
    save(d); sys.exit(0)
if argv[:2] == ['release', 'view']:
    phase('view')
    tag = argv[2]; d = load()
    if tag not in d: fail('Not Found')
    r = dict(d[tag])
    # Match the real gh CLI's --json selectors, not REST response fields.
    # In particular, "html_url" is REST-only; gh release view exposes "url".
    fields = {'isDraft': r['draft'], 'isPrerelease': r['prerelease'],
              'assets': [{'name': a['name'], 'url': a['url']} for a in r['assets']],
              'url': r['html_url'], 'tagName': r['tag_name'],
              'body': r['body']}
    if '--json' not in argv:
        fail('gh_mock: --json selector required')
    requested = argv[argv.index('--json') + 1].split(',')
    for key in requested:
        if key not in fields:
            fail(f'Unknown JSON field: "{key}"')
    print(json.dumps({key: fields[key] for key in requested}))
    sys.exit(0)
if argv[:2] == ['release', 'download']:
    tag = argv[2]; d = load()
    if tag not in d: fail('Not Found')
    pat = argv[argv.index('--pattern') + 1]
    outdir = argv[argv.index('--dir') + 1]
    os.makedirs(outdir, exist_ok=True)
    for a in d[tag]['assets']:
        if a['name'] == pat:
            dst = Path(outdir) / a['name']
            shutil.copy2(a['path'], dst)
            if os.environ.get('GH_MOCK_TAMPER_ASSET') == a['name']:
                with dst.open('ab') as f: f.write(b'tampered')
            sys.exit(0)
    fail(f'no asset matched {pat}')
if argv[:2] == ['release', 'edit']:
    phase('edit')
    tag = argv[2]; d = load()
    if tag not in d: fail('Not Found')
    if '--draft=false' in argv: d[tag]['draft'] = False
    save(d); sys.exit(0)
fail(f'gh_mock: unsupported invocation: {argv}')
