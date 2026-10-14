#!/usr/bin/env python3
"""Generate tests/pkits/manifest.json from the NIST PKITS description.

Usage:
    pdftotext -layout PKITS.pdf PKITS.txt
    python3 -I tests/scripts/pkits-manifest.py PKITS.txt tests/pkits > tests/pkits/manifest.json

Each Section 4 test lists its certification path (trust anchor first, end
entity last) and expected result. Policy tests may describe several numbered
inputs, each with its own initial-policy-set, initial-explicit-policy and
expected result; every such input becomes one run.
"""

import json
import os
import re
import sys

HEADER = re.compile(r"^\s*(4\.\d+\.\d+)\s+(.*?Test\s?\d+[a-z]?)\W*$")
ANY_POLICY = "2.5.29.32.0"
TITLE_OUTCOME = {"Valid": "valid", "Invalid": "invalid"}


def nist_policy(name):
    number = re.search(r"NIST-test-policy-(\d+)", name)
    if number:
        return f"2.16.840.1.101.3.2.1.48.{number.group(1)}"
    if "any" in name:
        return ANY_POLICY
    raise ValueError(f"unknown policy name {name!r}")


def outcome(text):
    # PKITS 4.4.20 and 4.4.21 read "The path not should validate".
    if "should not validate" in text or "not should validate" in text:
        return "invalid"
    if "should validate successfully" in text:
        return "valid"
    return None


def settings(text):
    run = {}
    if re.search(r"initial-explicit-policy (indicator )?set", text):
        run["explicitPolicy"] = True
    initial = re.search(r"initial-policy-set\s*=\s*\{([^}]*)\}", text)
    if initial:
        run["initialPolicySet"] = [nist_policy(n.strip()) for n in initial.group(1).split(",") if n.strip()]
    if "initial-policy-mapping-inhibit set" in text:
        run["policyMappingInhibit"] = True
    if "initial-inhibit-any-policy set" in text:
        run["anyPolicyInhibit"] = True
    return run


def candidate_file(data_dir, item):
    name = item.replace(" ", "").replace("-", "")
    for candidate in (f"certs/{name}.crt", f"crls/{name}.crl"):
        if os.path.exists(os.path.join(data_dir, candidate)):
            return candidate
    return None


def resolve(data_dir, item):
    candidate = candidate_file(data_dir, item)
    if candidate is None:
        raise FileNotFoundError(f"no file for PKITS object {item!r}")
    return candidate


def path_objects(body, data_dir):
    """Returns the certification path objects. A wrapped line continues the
    previous bullet only while its last object does not name a file yet."""
    bullets, in_path = [], False
    for raw in body:
        line = raw.strip()
        if "Certification Path:" in raw:
            in_path = True
        elif in_path and re.match(r"^\d+(\.\d+)*\s", line):
            break  # next numbered heading
        elif in_path and line.startswith("•"):
            bullets.append(line.lstrip("•").strip())
        elif in_path and bullets and line and not line.isdigit():
            last = bullets[-1].split(",")[-1].strip()
            if bullets[-1].rstrip().endswith(",") or candidate_file(data_dir, last) is None:
                bullets[-1] += " " + line  # wrapped bullet
    return [item.strip() for bullet in bullets for item in bullet.split(",") if item.strip()]


def main():
    text_path, data_dir = sys.argv[1:3]
    lines = open(text_path, encoding="utf-8", errors="replace").read().split("\n")
    starts = [(i, m.group(1), re.sub(r"\s+", " ", m.group(2))) for i, line in enumerate(lines) if (m := HEADER.match(line))]

    tests, seen = [], set()
    for position, (index, test_id, title) in enumerate(starts):
        if test_id in seen:
            continue
        seen.add(test_id)
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        body = lines[index + 1:end]
        for cut, line in enumerate(body):
            if "Relationship to Previous Test Suite" in line or line.strip().startswith("6 Test Data Descriptions"):
                body = body[:cut]
                break
        joined = re.sub(r"\s+", " ", " ".join(body))
        intro = joined.split("Procedure:")[0]
        expected = re.search(r"Expected Result:\W*(.*?)(?:Certification Path:|$)", joined)
        procedure = re.search(r"Procedure:\W*(.*?)(?:Expected Result:|$)", joined)

        runs = []
        for item in re.findall(r"(?:^|\s)\d\.\s+(default settings.*?)(?=\s\d\.\s+default settings|$)", intro):
            if outcome(item):
                runs.append({**settings(item), "expected": outcome(item)})
        if not runs:
            # Expected results of policy tests are often conditional ("if the
            # application can process policyConstraints ... otherwise ..."),
            # so the title, which PKITS prefixes with the conformant outcome,
            # is authoritative. Untitled tests fall back to the text.
            result = TITLE_OUTCOME.get(title.split(" ")[0]) or outcome(expected.group(1))
            runs.append({**settings(procedure.group(1) if procedure else ""), "expected": result})

        files = [resolve(data_dir, item) for item in path_objects(body, data_dir)]
        certificates = [f for f in files if f.startswith("certs/")]
        if not certificates[-1].endswith("EE.crt"):
            raise ValueError(f"{test_id}: path does not end with an end-entity certificate")
        tests.append({
            "id": test_id,
            "title": title,
            "ee": certificates[-1],
            "issuers": certificates[:-1],
            "crls": [f for f in files if f.startswith("crls/")],
            "runs": runs,
        })

    if len(tests) != 224 or any(run["expected"] is None for t in tests for run in t["runs"]):
        raise SystemExit(f"unexpected parse result: {len(tests)} tests")
    json.dump({
        "source": {
            "suite": "NIST Public Key Interoperability Test Suite (PKITS) 1.0.1",
            "url": "https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS_data.zip",
            "description": "https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents/PKITS.pdf",
        },
        "tests": tests,
    }, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
