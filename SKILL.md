---
name: finding-triage-gate
description: Run a seven-question gate on a single bug bounty finding before any report is written — check the attacker can act right now, the harm is real, the target is in scope, no duplicate exists, and the impact is proven, and stop the finding when any question fails.
summary: Gate a bug bounty finding through seven questions before writing a report — pass, gather evidence, or stop.
version: 1.0.0
tags:
  - bug-bounty
  - triage
  - validation
  - security
  - web3
  - smart-contract
  - report
  - hunting
keywords:
  - bug bounty triage
  - finding validation
  - duplicate check
  - severity
  - proof of concept
  - scope check
  - submission gate
use_cases:
  - Check a bug bounty finding before writing a report
  - Stop a theoretical finding or a duplicate before it costs a submission
  - List exactly what evidence is still missing for a plausible finding
---

# Finding Triage Gate

Run seven questions over a single bug bounty finding, in order,
before any report is written. A finding that passes all seven is
ready to be drafted as a report. A finding with no failures but
missing evidence goes back for the missing evidence. A finding
that fails any question stops here: no report is written, and the
hunter moves on to the next lead.

Use this skill when the user has a candidate finding from a
bounty program and wants to know whether it is worth reporting,
what evidence is still missing, or why it should be dropped.

Do NOT use it to find bugs, to audit code, or to write a report.
It gates one finding the hunter already has. It does not hunt,
and it does not submit anything to any platform.

## The core test

One question sits behind the whole gate: could an attacker do
this today, against an ordinary user who did nothing out of the
ordinary, and cause concrete harm? If the answer is no, the
finding stops — however interesting the code looks. A report
built on a theoretical bug wastes the hunter's time and damages
the hunter's standing with the program when it comes back
rejected.

## What this skill does NOT do

This skill never submits a report, never contacts a bounty
program, and never runs a test against a live target. Every
state-changing action — submitting a report, or testing
anything beyond the program's safe-harbor terms — needs the
creator's explicit instruction for that exact action. A PASS
verdict is not an instruction to submit: the exact report draft
still needs the creator's explicit approval before it goes
anywhere.

## Standing rules

These rules come first, and they override any other advice in
this skill:

- Verify every claim first: a local proof-of-concept run, an
  on-chain read, or the source code. Never invent, overstate,
  or soften a finding.
- A proof of concept is mandatory for every severity. A finding
  without executed proof is not ready to report.
- Duplicates earn nothing. Check the program's known issues
  and published audits before writing anything.
- Never submit any report without the creator's explicit
  approval of the exact draft.
- Test on local forks only. Never test on mainnet or a public
  testnet.
- Read the program's full scope before touching any asset.
  One out-of-scope report is closed on arrival.

## Requirements

Python 3, a terminal, and read and write access to the working
files. No network calls, no API key, nothing to install. The
gate is `scripts/gate.py`, standard library only,
self-contained. The checks the gate scores — reading the
program page, searching known issues, running a proof of
concept — are done with the agent's own tools; the gate only
scores the finding the agent puts in the input file.

## Workflow

### 1. Gather the finding

Ask for, or read from the hunter's notes, one finding: its
title, program, target, and a short description. Then fill in
the seven inputs the gate scores. Read each one from a real
source — never from memory or from a guess:

- `attacker_action`: the exact steps the attacker runs, in
  order, written as concrete actions. If the steps cannot be
  written as concrete actions, the finding is not ready.
- `victim_action`: what the victim must do. Use `"none"` when
  the victim does nothing unusual. When the victim must act,
  also set `victim_action_unusual` to true when the action is
  something an ordinary user would not normally do.
- `impact`: the concrete harm — what the attacker walks away
  with. "Could allow access" is not concrete harm. Name the
  data, the funds, or the account.
- `impact_accepted_by_program`: true when this kind of impact
  is on the program's accepted list, false when it is on the
  excluded list, null when nobody has checked the program page.
- `in_scope`: true when the target is on the program's
  in-scope list, false when it is not, null when nobody has
  checked.
- `attacker_privilege`: what access the attacker needs —
  `none`, `free-account`, `low-priv`, `admin`, `physical`, or
  `compromised-victim`.
- `duplicate_check`: what was searched — `known-issues`,
  `published-audits`, `disclosed-reports` — and set
  `duplicate_found` to true when a duplicate was found.
- `evidence`: each item with a `type` and a `detail`. Types
  are `poc-local-fork` (a proof of concept run on a local
  fork), `onchain-read` (a live chain read showing the result),
  `source-code` (the vulnerable code, not yet run), or `none`.
- `severity_claim`: the severity the hunter would claim —
  `critical`, `high`, `medium`, `low`, or `informational`.

Put it in a finding file: one JSON object with the fields
above. See `reference/triage-rules.md` for the full schema and
what evidence satisfies each question.

Refuse a finding that is not JSON, or that lacks a title,
program, target, description, attacker action, victim action,
impact, evidence array, duplicate-check array, or severity
claim. Never invent steps, evidence, a scope answer, or a
duplicate search the hunter did not do. If the hunter has no
real finding yet, offer `examples/sample-finding-pass.json` as
a test first, and say clearly that it is invented sample data,
not a real finding.

### 2. Run the gate

Run the gate from the skill folder. It writes a gate report
and prints the verdict.

```bash
python3 scripts/gate.py --input finding.json --output gate.json
```

The gate reads only the finding file given on the command line.
It makes no network calls and reads no other file. If it exits
with an error, report the error exactly and do not hand-write a
gate report to replace it.

### 3. Present the verdict and the evidence gaps

Report the gate before any report is drafted:

- The verdict: PASS, NEEDS-EVIDENCE, or FAIL, with the
  per-question results.
- The stop reason, when the verdict is FAIL: the first failing
  question, in plain words.
- The evidence gaps, when the verdict is NEEDS-EVIDENCE: each
  missing piece, named exactly, so the hunter knows what to
  go and get.
- The severity note, when one is present: a claimed critical
  or high severity without proven impact must be lowered
  until the impact is proven.

A FAIL verdict means stop: do not draft a report, do not spend
more time on this lead, and move on. A NEEDS-EVIDENCE verdict
means gather the named evidence first and run the gate again —
do not write a report while any question still needs evidence.
A PASS verdict means the finding is ready to be drafted as a
report, and nothing more: the exact draft still needs the
creator's explicit approval before it is submitted anywhere.

## Files

- `SKILL.md` — this workflow.
- `scripts/gate.py` — the complete seven-question gate in
  dependency-free Python 3. Run it as shown above. It takes
  `--input` and `--output`.
- `reference/triage-rules.md` — the seven question definitions,
  what evidence satisfies each one, the duplicate-check
  procedure, severity guidance, the never-submit list, and the
  classes that are only valid with a chain.
- `examples/sample-finding-pass.json` — an invented finding
  that passes all seven questions. Its gate report is in
  `examples/sample-gate-pass.json`.
- `examples/sample-finding-fail.json` — an invented theoretical
  finding that fails the gate. Its gate report is in
  `examples/sample-gate-fail.json`.
- `examples/sample-finding-needs-evidence.json` — an invented
  plausible finding with no proof of concept yet. Its gate
  report is in `examples/sample-gate-needs-evidence.json`.

## Provenance

Built from proven bounty practice: read the scope first, test
only what an attacker can do today to an ordinary user, prove
the impact with a run instead of a reading, check for
duplicates before writing, and never submit a report the
creator has not approved word for word.
