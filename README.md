# OCTA-CoC — Automated Digital Chain-of-Custody Tracker

A **local, terminal-driven digital-forensics prototype** for recording evidence registration, custody handovers, integrity checks, suspicious activity and case-level PDF reports. Developed during a cybersecurity internship at Octagon Cybersecurity Nigeria Ltd.

> **Project status:** Eight planned implementation phases have been reported complete by the developer. Source inspection confirms that the eight associated Python modules are present, but there are integration gaps and security limitations documented below. OCTA-CoC is a research/educational prototype, **not a certified forensic evidence management system**.

## Why OCTA-CoC?

Digital evidence must be identifiable, attributable to a case and custodian, and accompanied by a record of handling and integrity checks. A manual custody ledger can lose context or conceal unauthorized modification. OCTA-CoC explores whether append-oriented records, cryptographic checksums, constrained custody transitions and independently stored audit anchors can improve traceability. These controls help reveal tampering; they do not guarantee authenticity or legal admissibility.

## Capabilities and implementation status

| Capability | Implementation | Important qualification |
| --- | --- | --- |
| Case, user, location, evidence, custody and audit tables | `src/database.py` | SQLite triggers reject UPDATE/DELETE on **CustodyRecord** and **AuditLog**, not on all tables. |
| Evidence file fingerprint | `src/evidence.py`, `src/coc_hash_chain.py` | SHA-256 at registration; later comparison requires the original/reference file. |
| Case audit hash chain and anchors | `src/coc_hash_chain.py` | Anchor log is a separate **local file**, not independently hosted or cryptographically signed. |
| Custody lifecycle and rejected transfers | `src/state_machine.py` | Validates two distinct known user IDs and the releasing custodian; this is not identity-proof cryptographic co-signing. |
| Terminal user interface | `src/main.py` | Case/user creation and core actions available; **menu options 4 and 5 are placeholders** although reporting and alerts have separate modules. |
| Transit threshold and access-violation records | `src/alerts.py` | Manual callable check (48 hours by default); no background alert delivery. |
| PDF report with post-generation hash | `src/reporting.py` | Requires ReportLab; directly runnable demo; not currently wired into menu option 4. |
| Adversarial test scenarios | `src/pentest.py` | Code writes `PENTEST_RESULTS.md`; results should be generated and reviewed locally before reporting a pass. |

## Project layout

```text
README.md                      # project landing page
src/
  database.py                 # SQLite schema and WORM triggers
  coc_hash_chain.py           # file hashing, chain and local anchor log
  evidence.py                 # evidence registration and lookup
  state_machine.py            # authorized transfer transitions
  main.py                     # terminal interface
  alerts.py                   # threshold and violation functions
  reporting.py                # PDF report generation
  pentest.py                  # adversarial test scenarios
docs/
  README.md                   # documentation index
  research/                   # original research reports and companion notes
  architecture.md             # modules and data flows
  security-design.md          # assumptions, guarantees and limitations
  testing.md                  # test instructions and coverage
diagram/
  Entity Relationship Diagram.jpeg  # existing conceptual ERD
  architecture.mmd            # additional text-based architecture diagram
```

Runtime files such as `src/octa_coc.db`, generated PDFs, anchor logs and `__pycache__` should not be regarded as source documentation or production test evidence.

## Quick start

Requirements: **Python 3** and the Python standard library; install ReportLab for PDF reports. The repository was inspected remotely, **not executed in this review**.

```bash
git clone https://github.com/Etim-Busola/Automated-Digital-Chain-of-Custody-Tracker.git
cd Automated-Digital-Chain-of-Custody-Tracker
python -m pip install reportlab     # only needed for PDF reporting
python src/main.py
```

From the terminal menu, the available core demonstration flow is:

1. Select **9** to load sample users, a storage location and a mock evidence file.
2. Select **8** to open a case (assign it to an existing user).
3. Select **1** to register the mock file against the case and its current custodian.
4. Select **2** to move evidence from `Logged` to `In Transit` using two different registered user IDs.
5. Select **3** to inspect the audit history; select **6** to verify the hash chain and anchor comparison.
6. Select **0** to exit.

The app creates/opens a SQLite database in `src/`; use **only synthetic demonstration data**. The current code does **not** provide end-to-end PDF reporting or threshold-checking through menu options 4/5; both functions can be demonstrated independently:

```bash
python src/alerts.py
python src/reporting.py
python src/pentest.py
```

Individual phases can also be demonstrated by running the other `src/*.py` modules directly. `pentest.py` writes `src/PENTEST_RESULTS.md`; this review does not assert its execution results.

## Evidence lifecycle

```mermaid
stateDiagram-v2
    [*] --> Logged
    Logged --> "In Transit"
    "In Transit" --> "Under Analysis"
    "In Transit" --> "Secured Storage"
    "Under Analysis" --> "In Transit"
    "Under Analysis" --> "Secured Storage"
    "Secured Storage" --> "In Transit"
    "Secured Storage" --> Disposed
    Disposed --> [*]
```

This is a controlled **application workflow**: the database does not independently enforce every state transition on direct SQL writes.

## Integrity model in brief

Each file receives a SHA-256 digest when registered. Each case starts an audit sequence at `SHA256("GENESIS|" + CaseID + "|" + DateOpened)`. Audit entries include a previous hash and hash of selected entry fields plus a timestamp; separate local anchor-log lines record the resulting entry hashes. Verification detects many unauthorized edits and full-chain rewrites **when the anchor file remains outside the attacker's control**. This is not a digital signature or a trusted time-stamping service.

Read [security design](docs/security-design.md) and [testing/limitations](docs/testing.md) before using any security claims in a report.

## Research and forensic context

The project draws on principles of forensic handling, the scope of **ISO/IEC 27037** (identification, collection, acquisition and preservation of digital evidence), and Nigerian electronic-evidence admissibility considerations. These are **research influences**, not evidence of certified ISO compliance or a legal admissibility determination. See [research notes](docs/research/implementation-context.md) and the original reports in `docs/research/`.

## Documentation

- [Documentation index](docs/README.md)
- [System architecture](docs/architecture.md)
- [Security design and limitations](docs/security-design.md)
- [Testing methodology](docs/testing.md)
- [Research-to-implementation context](docs/research/implementation-context.md)
- [Existing ERD](diagram/Entity%20Relationship%20Diagram.jpeg)

## Limitations and next steps

The next engineering priorities are connecting menu options 4/5 to their implemented modules, improving security authorization beyond user-ID entry, protecting anchors using independent storage, transactional coordination across audit and anchor writes, checking evidence hash modifications, and converting penetration-test outputs into reproducible evidence. See the [documentation audit](DOCUMENTATION_AUDIT.md) for details.

## Acknowledgement

OCTA-CoC was developed by Busola Etim as a cybersecurity internship project at Octagon Cybersecurity Nigeria Ltd. References to forensic practices and laws are for educational research, not legal advice.
