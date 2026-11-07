#!/usr/bin/env python3
"""Conformance tests for tcpflow (see SPEC.md, section 15).

    conformance.py generate <reference tcpflow>   write tests/golden/
    conformance.py check <tcpflow> [case ...]     compare against tests/golden/
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
GOLDEN = os.path.join(TESTS, "golden")
EXPECTED = os.path.join(GOLDEN, "EXPECTED_DIFFERENCES")
TIMEOUT = 30  # seconds per case; a hang is a bug, never a golden result

RUNS = {
    "default": [],
    "all": ["-a"],
    "index": ["-I", "-Ft"],
    "bins": ["-Fk", "-Fc"],
    "template": ["-T", "%T-%A.%a-%B.%b-%#"],
    "limit": ["-b", "100"],
    "pcap": ["-K"],
    "console": ["-c"],
    "console-hdr": ["-C", "-s"],
    "hex": ["-c", "-D"],
}
CONSOLE_RUNS = {"console", "console-hdr", "hex"}
NOT_COMPARED = {"report.xml", "report.pdf"}


def pcaps():
    found = []
    for d in ("tests", "tests/test8", "samplePcaps"):
        for name in sorted(os.listdir(os.path.join(ROOT, d))):
            if name.endswith((".pcap", ".cap")):
                found.append(os.path.join(d, name))
    return found


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fileobjects(report):
    """The <fileobject> elements of a report, as sorted canonical JSON lines."""
    try:
        root = ET.parse(report).getroot()
    except (ET.ParseError, OSError) as e:
        return ["<unreadable report: %s>" % e]
    nested = {id(fo) for br in root.iter("byte_run") for fo in br.iter("fileobject")}
    lines = []
    for fo in root.iter("fileobject"):
        if id(fo) in nested:
            continue
        lines.append(json.dumps(canonical(fo), sort_keys=True))
    return sorted(lines)


def canonical(elem):
    out = {}
    if elem.attrib:
        out["@"] = dict(elem.attrib)
    text = (elem.text or "").strip()
    if text:
        out["#"] = text
    for child in elem:
        out.setdefault(child.tag, []).append(canonical(child))
    return out


def is_flow_file(name):
    """Only flow files get the flow start time as mtime (SPEC.md 5.4)."""
    return not (name.endswith((".findx", ".pcap")) or "-HTTPBODY-" in name)


def run_case(binary, pcap, run):
    """Run one case in a scratch directory and return its result as a dict."""
    work = tempfile.mkdtemp(prefix="tcpflow-conformance-")
    try:
        args = [binary] + RUNS[run]
        if run not in CONSOLE_RUNS:
            args += ["-o", "out"]
        args += ["-r", os.path.join(ROOT, pcap)]
        try:
            p = subprocess.run(args, cwd=work, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, timeout=TIMEOUT)
            status, stdout = p.returncode, p.stdout
        except subprocess.TimeoutExpired:
            status, stdout = "timeout", b""
        result = {"status": status, "files": {}}
        if run in CONSOLE_RUNS:
            result["stdout"] = hashlib.sha256(stdout).hexdigest()
        out = os.path.join(work, "out")
        for dirpath, _, names in os.walk(out):
            for name in names:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, work)
                if name in NOT_COMPARED:
                    continue
                st = os.stat(path)
                entry = {"size": st.st_size, "sha256": sha256(path)}
                if is_flow_file(name):
                    entry["mtime_us"] = st.st_mtime_ns // 1000
                result["files"][rel] = entry
        report = os.path.join(out, "report.xml")
        if os.path.exists(report):
            result["fileobjects"] = fileobjects(report)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def case_id(pcap, run):
    return "%s:%s" % (pcap, run)


def golden_path(pcap, run):
    return os.path.join(GOLDEN, pcap.replace("/", "_") + "." + run + ".json")


def run_all(binary, cases):
    """Run cases in parallel; results come back in the order of cases."""
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as pool:
        return list(pool.map(lambda c: run_case(binary, *c), cases))


def broken(result):
    """A timeout or a crash (killed by a signal) is never acceptable behaviour."""
    status = result["status"]
    return status == "timeout" or (isinstance(status, int) and status < 0)


def generate(binary):
    os.makedirs(GOLDEN, exist_ok=True)
    cases = [(pcap, run) for pcap in pcaps() for run in RUNS]
    results = run_all(binary, cases)
    bad = [(c, r["status"]) for c, r in zip(cases, results) if broken(r)]
    if bad:
        for (pcap, run), status in bad:
            print("BROKEN %s: %s" % (case_id(pcap, run), status), file=sys.stderr)
        sys.exit("refusing to write golden data: fix the reference binary first")
    for (pcap, run), result in zip(cases, results):
        with open(golden_path(pcap, run), "w") as f:
            json.dump(result, f, indent=1, sort_keys=True)
            f.write("\n")
    print("wrote %d cases to %s" % (len(cases), os.path.relpath(GOLDEN, ROOT)))


def expected_differences():
    known = {}
    if os.path.exists(EXPECTED):
        for line in open(EXPECTED):
            line = line.strip()
            if line and not line.startswith("#"):
                cid, _, reason = line.partition(" ")
                known[cid] = reason.strip()
    return known


def describe(golden, got):
    problems = []
    if golden["status"] != got["status"]:
        problems.append("exit status %s, expected %s" % (got["status"], golden["status"]))
    if golden.get("stdout") != got.get("stdout"):
        problems.append("stdout differs")
    gf, nf = golden["files"], got["files"]
    for name in sorted(set(gf) - set(nf)):
        problems.append("missing " + name)
    for name in sorted(set(nf) - set(gf)):
        problems.append("unexpected " + name)
    for name in sorted(set(gf) & set(nf)):
        for key in ("size", "sha256", "mtime_us"):
            if gf[name].get(key) != nf[name].get(key):
                problems.append("%s: %s differs" % (name, key))
    if golden.get("fileobjects") != got.get("fileobjects"):
        problems.append("report.xml <fileobject> entries differ")
    return problems


def check(binary, selected):
    known = expected_differences()
    cases = [(pcap, run) for pcap in pcaps() for run in RUNS
             if not selected or any(s in case_id(pcap, run) for s in selected)]
    total, passed, expected = len(cases), 0, 0
    for (pcap, run), got in zip(cases, run_all(binary, cases)):
        cid = case_id(pcap, run)
        with open(golden_path(pcap, run)) as f:
            golden = json.load(f)
        problems = describe(golden, got)
        if broken(got):
            problems.insert(0, "hang or crash: %s" % got["status"])
        if not problems:
            passed += 1
        elif cid in known:
            expected += 1
            print("EXPECTED %s (%s)" % (cid, known[cid]))
        else:
            print("FAIL %s" % cid)
            for p in problems[:10]:
                print("    " + p)
            if len(problems) > 10:
                print("    ... %d more" % (len(problems) - 10))
    print("%d of %d cases match (%d expected differences)" % (passed, total, expected))
    return passed + expected == total


def main(argv):
    if len(argv) >= 3 and argv[1] == "generate":
        generate(os.path.abspath(argv[2]))
        return 0
    if len(argv) >= 3 and argv[1] == "check":
        return 0 if check(os.path.abspath(argv[2]), argv[3:]) else 1
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
