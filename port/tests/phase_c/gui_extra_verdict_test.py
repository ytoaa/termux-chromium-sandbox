#!/usr/bin/env python3
# C.2-A regression: evaluate_verdict gate matrix (pure function, no browser).
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gui_extra import evaluate_verdict, REQUIRED_CHECKS

def mk(**overrides):
    c = {k: {'pass': True} for k in REQUIRED_CHECKS}
    for k, v in overrides.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    return c

cases = []
# 1 all required pass
cases.append(('all-pass', mk(), 'PASS', 0))
# 2 no GUI window
cases.append(('no-window', mk(**{'gui-window-present': {'pass': False}}), 'FAIL', 1))
# 3 sha mismatch
cases.append(('dl-sha-mismatch', mk(**{'download-gui-cdp': {'pass': False}}), 'FAIL', 1))
# 4 no completion event
cases.append(('dl-no-event', mk(**{'download-gui-cdp': {'pass': False,
           'detail': {'done': False}}}), 'FAIL', 1))
# 5 required check missing entirely
cases.append(('missing-webgl', mk(**{'webgl-default': None}), 'FAIL', 1))
cases.append(('missing-key-garbage', dict(((k, {'pass': True}) for k in
           REQUIRED_CHECKS if k != 'audio-sink-input-pactl')), 'FAIL', 1))
# 6 webgl fail
cases.append(('webgl-fail', mk(**{'webgl-default': {'pass': False}}), 'FAIL', 1))
# 7 chooser fail
cases.append(('chooser-fail', mk(**{'file-chooser-window': {'pass': False}}), 'FAIL', 1))
# 8 optional failures never flip
c8 = mk(); c8['gpu-info-page'] = {'pass': False}
cases.append(('optional-gpu-info-fail-ok', c8, 'PASS', 0))
c9 = mk(); c9['downloads-list-item'] = {'pass': True,
       'status': 'INCONCLUSIVE-allowed'}
cases.append(('optional-list-inconclusive-ok', c9, 'PASS', 0))
# 9 pass=None counts as failure (no exception/timeout PASS)
cases.append(('pass-none-fails', mk(**{'file-api-setinput': {'pass': None}}),
              'FAIL', 1))
fail = 0
for name, checks, want_verdict, want_rc in cases:
    verdict, missing, failed = evaluate_verdict(checks)
    rc = 0 if verdict == 'PASS' else 1
    ok = (verdict == want_verdict and rc == want_rc)
    if not ok:
        fail = 1
    print(('PASS ' if ok else 'FAIL ') + '[%s] verdict=%s rc=%d (want %s/%d) missing=%s failed=%s'
          % (name, verdict, rc, want_verdict, want_rc, missing, failed))
print('VERDICT-TESTS-RC=%d' % fail)
sys.exit(fail)
