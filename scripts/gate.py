#!/usr/bin/env python3
"""Finding Triage Gate — offline verdict for a single bug bounty finding.

Dependency-free Python 3, standard library only. No network calls,
no credentials, no live target access. It reads one finding JSON
file and writes one gate-report JSON file.

The gate asks seven questions, in order, about the finding:

  Q1  Can the attacker carry out the steps right now?
  Q2  Is there concrete harm to a real victim?
  Q3  Does the program accept this kind of impact?
  Q4  Is the target in scope?
  Q5  Does it need access the attacker cannot realistically get?
  Q6  Has it been checked against what is already known?
  Q7  Is the impact proven, and is this a class that is never paid?

Each question scores PASS, FAIL, or NEEDS-EVIDENCE. The overall
verdict is PASS when all seven pass, NEEDS-EVIDENCE when nothing
fails but at least one question still needs evidence, and FAIL
when any question fails. A FAIL names the first failing question
as the stop reason: stop there, do not write a report.

This script never writes a report, never contacts a program, and
never submits anything. It only scores the finding the agent puts
in the input file. Every claim in that file is the agent's
responsibility to have verified first.
"""

import argparse
import json
import sys

SEVERITIES = ("critical", "high", "medium", "low", "informational")
PRIVILEGES = ("none", "free-account", "low-priv", "admin", "physical",
              "compromised-victim")
DUPLICATE_SOURCES = ("known-issues", "published-audits", "disclosed-reports")
EVIDENCE_TYPES = ("poc-local-fork", "onchain-read", "source-code", "none")

# Words that mark attacker steps as guesswork rather than a concrete
# sequence an attacker can run today.
HEDGE_WORDS = ("could", "maybe", "potentially", "might", "possibly",
               "theoretically")


def fail(message):
    print(f"finding-triage-gate: {message}", file=sys.stderr)
    raise SystemExit(1)


def _string(finding, field, required=True):
    value = finding.get(field)
    if value is None:
        if required:
            fail(f"finding has no {field}")
        return None
    if not isinstance(value, str):
        fail(f"finding {field} must be a string")
    return value


def _optional_bool(finding, field):
    value = finding.get(field)
    if value is None:
        return None
    if not isinstance(value, bool):
        fail(f"finding {field} must be true or false")
    return value


def load_finding(path):
    try:
        with open(path, encoding="utf-8") as handle:
            finding = json.load(handle)
    except OSError as error:
        fail(f"cannot read finding: {error}")
    except json.JSONDecodeError as error:
        fail(f"finding is not valid JSON: {error}")
    if not isinstance(finding, dict):
        fail("finding must be a JSON object")
    for field in ("title", "program", "target", "description",
                  "attacker_action", "victim_action", "impact"):
        if not _string(finding, field):
            fail(f"finding has no {field}")
    severity = finding.get("severity_claim")
    if severity not in SEVERITIES:
        fail("finding severity_claim must be one of: " + ", ".join(SEVERITIES))
    privilege = finding.get("attacker_privilege")
    if privilege is not None and privilege not in PRIVILEGES:
        fail("finding attacker_privilege must be one of: " + ", ".join(PRIVILEGES))
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        fail("finding evidence must be an array")
    for item in evidence:
        if not isinstance(item, dict) or item.get("type") not in EVIDENCE_TYPES:
            fail("each evidence item needs a type of: " + ", ".join(EVIDENCE_TYPES))
        if "detail" in item and not isinstance(item["detail"], str):
            fail("each evidence item detail must be a string")
    duplicate_check = finding.get("duplicate_check")
    if not isinstance(duplicate_check, list):
        fail("finding duplicate_check must be an array")
    for source in duplicate_check:
        if source not in DUPLICATE_SOURCES and source != "none":
            fail("duplicate_check entries must be one of: "
                 + ", ".join(DUPLICATE_SOURCES) + ", none")
    return {
        "title": finding["title"],
        "program": finding["program"],
        "target": finding["target"],
        "description": finding["description"],
        "attacker_action": finding["attacker_action"],
        "victim_action": finding["victim_action"],
        "victim_action_unusual": _optional_bool(finding, "victim_action_unusual"),
        "impact": finding["impact"],
        "impact_accepted_by_program": _optional_bool(
            finding, "impact_accepted_by_program"),
        "in_scope": _optional_bool(finding, "in_scope"),
        "attacker_privilege": privilege,
        "duplicate_check": duplicate_check,
        "duplicate_found": _optional_bool(finding, "duplicate_found"),
        "evidence": evidence,
        "known_invalid_class": _optional_bool(finding, "known_invalid_class"),
        "severity_claim": severity,
    }


def _evidence_has(finding, types):
    return any(item.get("type") in types and item.get("detail")
               for item in finding["evidence"])


def gate(finding):
    questions = []

    # Q1 — Can the attacker carry out the steps right now?
    steps = finding["attacker_action"].strip()
    victim = finding["victim_action"].strip().lower()
    victim_unusual = finding["victim_action_unusual"] is True
    if victim_unusual:
        questions.append(("Q1", "FAIL",
                          "The finding needs the victim to do something "
                          "unusual. An attacker cannot do this right now "
                          "on their own."))
    elif not steps:
        questions.append(("Q1", "FAIL", "No attacker steps are written down."))
    elif any(word in steps.lower() for word in HEDGE_WORDS):
        questions.append(("Q1", "NEEDS-EVIDENCE",
                          "The attacker steps use guesswork words. Rewrite "
                          "them as concrete actions an attacker runs today."))
    elif victim != "none":
        questions.append(("Q1", "NEEDS-EVIDENCE",
                          "The attacker steps need the victim to act first. "
                          "The finding is only valid with a working chain "
                          "that makes the victim act."))
    else:
        questions.append(("Q1", "PASS",
                          "Attacker steps are written as concrete actions "
                          "needing no victim action."))

    # Q2 — Is there concrete harm to a real victim?
    harm = finding["impact"].strip()
    if not harm:
        questions.append(("Q2", "FAIL", "No concrete harm is stated."))
    elif victim_unusual:
        questions.append(("Q2", "FAIL",
                          "The harm only happens if the victim does "
                          "something unusual, so there is no real victim."))
    elif any(word in harm.lower() for word in HEDGE_WORDS):
        questions.append(("Q2", "NEEDS-EVIDENCE",
                          "The harm is written as a guess. Name the exact "
                          "data, funds, or account the attacker walks away "
                          "with."))
    else:
        questions.append(("Q2", "PASS",
                          "Concrete harm to a real victim is stated."))

    # Q3 — Does the program accept this kind of impact?
    accepted = finding["impact_accepted_by_program"]
    if accepted is True:
        questions.append(("Q3", "PASS",
                          "This kind of impact is on the program's "
                          "accepted list."))
    elif accepted is False:
        questions.append(("Q3", "FAIL",
                          "This kind of impact is on the program's "
                          "excluded list."))
    else:
        questions.append(("Q3", "NEEDS-EVIDENCE",
                          "Nobody has checked the program page for whether "
                          "this kind of impact is accepted or excluded."))

    # Q4 — Is the target in scope?
    in_scope = finding["in_scope"]
    if in_scope is True:
        questions.append(("Q4", "PASS",
                          "The target is on the program's in-scope list."))
    elif in_scope is False:
        questions.append(("Q4", "FAIL",
                          "The target is not in scope for this program."))
    else:
        questions.append(("Q4", "NEEDS-EVIDENCE",
                          "Nobody has checked the target against the "
                          "program's scope list."))

    # Q5 — Does it need access the attacker cannot realistically get?
    privilege = finding["attacker_privilege"]
    if privilege in ("none", "free-account", "low-priv"):
        questions.append(("Q5", "PASS",
                          f"Only {privilege} access is needed."))
    elif privilege in ("admin", "physical", "compromised-victim"):
        questions.append(("Q5", "FAIL",
                          f"The finding needs {privilege} access, which an "
                          "attacker cannot realistically get."))
    else:
        questions.append(("Q5", "NEEDS-EVIDENCE",
                          "Nobody has stated what access the attacker "
                          "needs."))

    # Q6 — Has it been checked against what is already known?
    checked = set(finding["duplicate_check"])
    if finding["duplicate_found"] is True:
        questions.append(("Q6", "FAIL",
                          "This finding is already known: a duplicate "
                          "earns nothing."))
    elif "known-issues" in checked and "published-audits" in checked:
        questions.append(("Q6", "PASS",
                          "Known issues and published audits were both "
                          "checked and no duplicate was found."))
    else:
        questions.append(("Q6", "NEEDS-EVIDENCE",
                          "Known issues and published audits have not both "
                          "been checked for this finding."))

    # Q7 — Is the impact proven, and is this a class that is never paid?
    if finding["known_invalid_class"] is True:
        questions.append(("Q7", "FAIL",
                          "This is a class of finding that programs do not "
                          "pay for on its own."))
    elif _evidence_has(finding, ("poc-local-fork", "onchain-read")):
        questions.append(("Q7", "PASS",
                          "The impact is shown with executed proof, not "
                          "just code reading."))
    elif _evidence_has(finding, ("source-code",)):
        questions.append(("Q7", "NEEDS-EVIDENCE",
                          "The impact is only shown in source code so far. "
                          "Run it and show the real result."))
    else:
        questions.append(("Q7", "FAIL",
                          "There is no evidence at all for the impact."))

    fails = [q for q in questions if q[1] == "FAIL"]
    needs = [q for q in questions if q[1] == "NEEDS-EVIDENCE"]
    if fails:
        verdict = "FAIL"
        stop_reason = f"{fails[0][0]}: {fails[0][2]}"
    elif needs:
        verdict = "NEEDS-EVIDENCE"
        stop_reason = None
    else:
        verdict = "PASS"
        stop_reason = None

    severity_note = None
    proven = questions[6][1] == "PASS"
    if finding["severity_claim"] in ("critical", "high") and not proven:
        severity_note = (
            f"Claimed severity is {finding['severity_claim']}, but the "
            "impact is not proven with executed evidence. Do not submit "
            "at that severity: lower it until the impact is proven."
        )

    if verdict == "PASS":
        next_action = ("Ready to draft a report. A report still needs the "
                       "creator's explicit approval of the exact draft "
                       "before anything is submitted.")
    elif verdict == "NEEDS-EVIDENCE":
        next_action = ("Gather the missing evidence first. Do not write a "
                       "report until every question passes.")
    else:
        next_action = ("Stop. Do not write a report for this finding. "
                       "Move on to the next lead.")

    return {
        "title": finding["title"],
        "program": finding["program"],
        "target": finding["target"],
        "severity_claim": finding["severity_claim"],
        "questions": [
            {"question": q, "result": r, "reason": reason}
            for q, r, reason in questions
        ],
        "verdict": verdict,
        "stop_reason": stop_reason,
        "evidence_gaps": [f"{q}: {reason}" for q, r, reason in questions
                          if r == "NEEDS-EVIDENCE"],
        "severity_note": severity_note,
        "next_action": next_action,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run the seven-question gate on a bug bounty finding.")
    parser.add_argument("--input", required=True, help="finding JSON file")
    parser.add_argument("--output", required=True, help="gate-report JSON file to write")
    args = parser.parse_args()
    finding = load_finding(args.input)
    report = gate(finding)
    # Write the report only after every check has passed, so a bad
    # finding never leaves a report behind.
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
    except OSError as error:
        fail(f"cannot write gate report: {error}")
    passed = sum(1 for q in report["questions"] if q["result"] == "PASS")
    print(f"verdict: {report['verdict']} | {passed}/7 questions pass"
          + (f" | stop: {report['stop_reason']}" if report["stop_reason"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
