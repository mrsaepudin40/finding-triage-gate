# finding-triage-gate

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python 3](https://img.shields.io/badge/python-3-blue)](scripts/gate.py)
[![API key: not required](https://img.shields.io/badge/API%20key-not%20required-brightgreen)](reference/triage-rules.md)

Run a seven-question gate on a single bug bounty finding before
any report is written: check the attacker can act right now, the
harm is real, the target is in scope, no duplicate exists, and the
impact is proven — and stop the finding when any question fails.

## What it does

Feed it a finding (a JSON file in the format in
`reference/triage-rules.md`) and it returns a gate report with one
verdict: **PASS**, **NEEDS-EVIDENCE**, or **FAIL**.

- **Seven questions, in order.** Q1 can the attacker act right
  now? Q2 is there real harm to a real victim? Q3 is the impact
  accepted by the program? Q4 is the target in scope? Q5 does it
  need unrealistic access? Q6 has it been checked against known
  issues and published audits? Q7 is the impact proven, and is it
  not a class that is never paid?
- **Stop on the first fail.** A FAIL names the exact question
  that failed as the stop reason, so no more time is spent on a
  finding that cannot be submitted.
- **Evidence gaps, listed plainly.** A NEEDS-EVIDENCE verdict
  lists every missing proof — what to run, read, or check next —
  instead of a vague "maybe".
- **Duplicate check is part of the gate.** A finding that matches
  a known issue or a published audit fails Q6. Duplicates earn
  zero, so they are caught before the report is written, not
  after.
- **Severity is checked, not trusted.** A claimed severity that
  the evidence does not support gets a severity note in the
  report. Never inflate, never soften.
- **No theoretical bugs.** The core rule: can an attacker do this
  RIGHT NOW against a real user who has taken NO unusual actions
  — and does it cause real harm? If no, stop.

## Run it

```bash
python3 scripts/gate.py --input finding.json --output gate.json
```

Python 3, standard library only. No network calls, no API key,
nothing to install. The gate only judges what is written in the
finding file: the evidence claims in it are the agent's job to
verify first (local proof-of-concept run, on-chain read, or source
code). `examples/sample-finding-pass.json` is an invented finding
for testing; its gate report is in
`examples/sample-gate-pass.json`. Sample data is clearly labelled
and is not a real finding.

## Files

- `SKILL.md` — the agent skill: the full workflow for gathering
  a finding, running the gate, presenting the verdict and the
  evidence gaps, and getting the hunter's explicit approval of
  the exact report draft before anything is submitted.
- `scripts/gate.py` — the complete gate in dependency-free
  Python 3.
- `reference/triage-rules.md` — the seven question definitions,
  what evidence satisfies each question, the duplicate-check
  procedure, severity guidance, and the never-submit list.
- `examples/` — three invented findings and their exact gate
  reports: one that passes, one that fails, and one that needs
  evidence.

## Honest limits

The gate checks the finding as written; it cannot verify the
truth of the evidence claims inside it — that verification is the
hunter's job and must be done before the gate runs. The skill
never writes a submission or submits anything: every report goes
to the hunter for explicit approval of the exact draft first. A
verdict of PASS is not a promise the program will pay.
