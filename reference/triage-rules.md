# Triage Rules

The rules behind the seven-question gate. The gate script
(`scripts/gate.py`) scores a finding from the fields in the
finding file; this document explains what each question means,
what counts as satisfying it, and what to do with the answer.

## The finding schema

One JSON object:

| Field | Type | Meaning |
|---|---|---|
| `title` | string, required | Short title naming the bug class, the target, and the impact. |
| `program` | string, required | The bounty program the finding belongs to. |
| `target` | string, required | The exact asset: endpoint, contract, or feature. |
| `description` | string, required | One or two sentences saying what is wrong. |
| `attacker_action` | string, required | The exact steps the attacker runs, in order. |
| `victim_action` | string, required | What the victim must do. `"none"` when the victim does nothing unusual. |
| `victim_action_unusual` | boolean, optional | True when the victim action is something an ordinary user would not normally do. |
| `impact` | string, required | The concrete harm: the data, the funds, or the account the attacker walks away with. |
| `impact_accepted_by_program` | true / false / null | Whether this kind of impact is on the program's accepted list. Null when unchecked. |
| `in_scope` | true / false / null | Whether the target is on the program's in-scope list. Null when unchecked. |
| `attacker_privilege` | string, optional | `none`, `free-account`, `low-priv`, `admin`, `physical`, or `compromised-victim`. |
| `duplicate_check` | array, required | What was searched: `known-issues`, `published-audits`, `disclosed-reports`, or `none`. |
| `duplicate_found` | boolean, optional | True when a search found this finding already known. |
| `evidence` | array, required | Each item: `type` plus `detail`. Types: `poc-local-fork`, `onchain-read`, `source-code`, `none`. |
| `known_invalid_class` | boolean, optional | True when the finding is in the never-submit list below. |
| `severity_claim` | string, required | `critical`, `high`, `medium`, `low`, or `informational`. |

## The seven questions, in order

### Q1 — Can the attacker carry out the steps right now?

The attacker steps must be written as concrete actions: the
request, the call, or the transaction, in order, with the values
filled in. Steps written with guesswork words — could, maybe,
potentially, might — are not concrete actions; rewrite them or
go back for the missing evidence.

The victim matters here too. When the victim must act first,
the finding is only as strong as the chain that makes the
victim act. When the victim must do something unusual — install
something from an unknown link, turn off a security setting,
import a crafted file — the attacker cannot do this on their
own, and the question fails.

### Q2 — Is there concrete harm to a real victim?

Name what the attacker walks away with: whose data, how much
money, which account. "Access might be possible" is not harm.
A finding whose only result is that something looks wrong,
with no data, funds, or account at stake, fails here.

### Q3 — Does the program accept this kind of impact?

Read the program page. Find its accepted impact list and its
exclusions. A finding whose impact class is listed as excluded
fails, however real the bug is. A finding nobody has checked
against the page yet needs evidence: go and read the page.

### Q4 — Is the target in scope?

Check the target against the program's scope list, asset by
asset. A production asset in scope passes. A staging or
development asset passes only when the program names it in
scope. A third-party service the company merely uses — a
payment provider, an identity provider, an email service —
is out of scope. An unchecked target needs evidence.

### Q5 — Does it need access the attacker cannot realistically get?

`none`, a free account, or a low-privilege account pass: any
attacker can get those. An admin account, physical access, or
an already-compromised victim account fail: the attacker cannot
realistically start there. "An admin can do this" is a
centralisation concern, not a bounty finding, on almost every
program.

### Q6 — Has it been checked against what is already known?

Search both of these before writing anything:

1. The program's known issues: its public issue list, its
   changelog, and its disclosed reports for the same endpoint
   or bug class.
2. Published audits of the target: the audit reports, their
   findings lists, and any fixes the audits already recorded.

Both searches must be done, with no duplicate found, to pass.
One search only, or neither, needs evidence. A duplicate found
fails outright: duplicates earn nothing, and writing the report
anyway spends the hunter's time for no payout.

### Q7 — Is the impact proven, and is this a class that is never paid?

Two checks in one question:

- **Proof.** The impact must be shown with something that was
  actually run: a proof of concept on a local fork, or a live
  on-chain read showing the result. Code reading alone is not
  proof — it needs evidence. No evidence at all fails.
- **Never-paid class.** Some classes are rejected on their own
  on almost every program. See the never-submit list below.
  A finding in one of those classes fails unless it is chained
  to real impact; see the chain table below.

## Severity guidance

- Claim the severity the proven impact supports, not the
  severity the bug class sounds like. A critical claim with
  unproven impact must be lowered until the impact is proven.
- Never inflate a severity to get attention: triagers trust a
  hunter less after one inflated claim, and the next real
  finding pays for it.
- Never understate the impact either: if the proof shows
  another user's funds moving, say so plainly with the amount.
- When the impact is only shown in source code, the highest
  honest claim is the one the code supports — and the finding
  still needs a run before it is submitted at that severity.

## Never-submit list

These classes, on their own, are rejected on almost every
program. Do not write them up alone:

- A missing security header on its own, with no working exploit
- A version banner or software version shown, with no working
  exploit for it
- An attack that only works against the attacker's own account
- Clickjacking on a page with no sensitive action behind it
- An open redirect with no token or session theft chained to it
- A logout request forgery
- A wildcard cross-origin rule with no proof that credentials
  or private data actually leak
- A rate limit missing on a form nobody pays to protect, such
  as search or contact
- A session that stays valid after logout, on its own
- A cookie flag missing on its own, with no session theft shown
- A broken link to an outside site
- An autocomplete setting on a password field

## Only valid with a chain

Some findings are real only when chained to a second step that
produces the harm. Build the chain first, prove it works end to
end, and only then report:

| Standalone finding | Chain it needs | Valid result |
|---|---|---|
| Open redirect | A login flow that hands the auth code to the redirected address | Account takeover |
| Clickjacking | A sensitive action behind the framed page, with a working demonstration | Medium |
| Wildcard cross-origin rule | A credentialed request that actually leaks private data | High |
| Cross-site request forgery | A sensitive action: move funds, change an email, delete an account | High |
| Missing rate limit | A brute-force that actually succeeds against a one-time code or reset token | Medium to High |
| DNS-only server-side request | Reaching an internal service that returns real data | Medium |
| Host header injection | A password reset email that uses the injected host | High |
| Self-scripting | A forgery that triggers it on the victim without the victim knowing | Medium |
| Subdomain takeover | A login redirect registered at that subdomain | Critical |
| Introspection on a query API | An auth bypass or another user's data reached through it | High |
| A leaked key on its own | Proof of what the key reaches: storage, a database, an admin panel | Medium to High |

A leaked credential without exploitation proof is informational.
Call the service as the leaked key and list what it can reach.

## Kill-fast rules

- If the attacker steps cannot be written concretely in five
  minutes, drop the lead and move on.
- More than two preconditions that must all hold at once means
  the finding is not real-world exploitable: drop it.
- Ask what the attacker walks away with. Nothing tangible
  means no finding.
- "An admin can do this" is never a finding: drop it at once.
- Documented behaviour is not a bug: drop it at once.
- Thirty minutes spent trying to prove the impact with no
  reproducible run means the lead is cold: drop it.

## Never submit without approval

A PASS verdict means the finding is ready to be drafted as a
report. It does not mean the report is submitted. The exact
draft — title, steps, evidence, severity — needs the creator's
explicit approval before it goes to any platform. No
submission happens on a verdict alone.
