#!/usr/bin/env python3
"""Exit-code stub for the publisher Execute step (Round 18 e-series).

Simulates port/publish_release.py execute returning an injected code
(STUB_RC) and records argv to STUB_ARGS so tests can prove the REAL
workflow step body actually invoked (and propagated) the publisher.
Optionally writes STUB_OUT_FILE to simulate a produced result doc.
"""
import os, sys
args = os.environ.get('STUB_ARGS')
if args:
    with open(args, 'w') as f:
        f.write('\n'.join(sys.argv[1:]))
out_file = os.environ.get('STUB_OUT_FILE')
if out_file and os.environ.get('STUB_RC', '0') == '0':
    with open(out_file, 'w') as f:
        f.write('{"status": "published"}\n')
sys.exit(int(os.environ.get('STUB_RC', '0')))
