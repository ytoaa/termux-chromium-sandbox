#!/usr/bin/env python3
"""Real Bash publish intent writer: strict consent + safe JSON + refusals."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "port/record_publish_intent.sh"
SHA = "2abda68e6a7a22c6251feddf54ceeff663bcb26e"
PASSED = FAILED = 0


def check(label, condition):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print("PASS  " + label)
    else:
        FAILED += 1
        print("FAIL  " + label)


def invoke(event="workflow_dispatch", requested="false", run="40316851934", sha=SHA,
           noevent=False):
    with tempfile.TemporaryDirectory() as d:
        env = os.environ.copy()
        env.update(SOURCE_RUN_ID=run, SOURCE_HEAD_SHA=sha)
        if noevent:
            env.pop("SOURCE_EVENT", None)
        else:
            env["SOURCE_EVENT"] = event
        if requested is None:
            env.pop("REQUESTED_PUBLISH", None)
        else:
            env["REQUESTED_PUBLISH"] = requested
        cp = subprocess.run(["bash", str(SCRIPT)], cwd=d, env=env,
                            capture_output=True, text=True)
        file = Path(d) / "publish-intent.json"
        try:
            doc = json.loads(file.read_text()) if file.exists() else None
        except ValueError:
            doc = "not JSON"
        return cp, doc


check("shell parser", subprocess.run(["bash", "-n", str(SCRIPT)]).returncode == 0)
cp, doc = invoke()
check("dispatch explicit false means publish false", cp.returncode == 0
      and doc == {"schema": 1, "event": "workflow_dispatch",
                  "run_id": "40316851934", "head_sha": SHA, "publish": False})
cp, doc = invoke(requested="true")
check("dispatch explicit true means publish true", cp.returncode == 0
      and doc["publish"] is True)
cp, doc = invoke(requested=None)
check("dispatch missing input is safely false", cp.returncode == 0
      and doc["publish"] is False)
cp, doc = invoke(event="workflow_call", requested="true")
check("reusable-call true never grants manual consent", cp.returncode == 0
      and doc["publish"] is False)
cp, doc = invoke(event="schedule", requested="true")
check("scheduled true never grants manual consent", cp.returncode == 0
      and doc["publish"] is False)
cp, doc = invoke(requested="TRUE")
check("ambiguous uppercase input refused", cp.returncode != 0 and doc is None)
cp, doc = invoke(requested="true\n\"publish\":true")
check("injected consent refused", cp.returncode != 0 and doc is None)
cp, doc = invoke(event="workflow_dispatch\nanything", requested="true")
check("event JSON injection refused", cp.returncode != 0 and doc is None)
cp, doc = invoke(run="1\"}")
check("run ID JSON injection refused", cp.returncode != 0 and doc is None)
cp, doc = invoke(sha="abc")
check("bad HEAD SHA refused", cp.returncode != 0 and doc is None)
cp, doc = invoke(noevent=True)
check("missing event refused", cp.returncode != 0 and doc is None)

print(f"PUBLISH-INTENT-TESTS PASS={PASSED} FAIL={FAILED}")
raise SystemExit(1 if FAILED else 0)
