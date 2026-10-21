# Automated Digital Chain of Custody Tracker

**OCTA-CoC** is a Python and SQLite prototype for recording digital evidence,
tracking custody transfers, and checking the integrity of case audit trails.
The repository also contains research and an entity relationship diagram for
the system.

## Project status

The project includes an interactive terminal application and supporting modules
for evidence registration, custody rules, audit hashing, alerts, and reporting.
PDF reporting and threshold alerts have module implementations, but options
**4** and **5** in the terminal menu currently display placeholder messages.

Research objectives include studying ISO/IEC 27037 and the Nigerian Evidence
Act. These are project objectives, not claims of certification or legal
compliance.

## Features

| Capability | Current implementation |
| --- | --- |
| Users and cases | Add users and open cases through the terminal menu. |
| Evidence registration | Record file metadata and a SHA-256 fingerprint against a case. |
| Custody tracking | Record transfers between different registered custodians and enforce allowed state changes. |
| Audit trail | Maintain a separate hash chain for each case and display its entries. |
| Integrity checks | Verify audit hashes and compare them with a local anchor log. |
| Record protection | SQLite triggers reject ordinary updates and deletes on `CustodyRecord` and `AuditLog`. |
| Threshold checks | `alerts.py` identifies evidence in transit for at least the configured limit, which defaults to 48 hours. |
| PDF reporting | `reporting.py` contains report generation and report fingerprint verification functions; CLI integration is pending. |
| Security demonstrations | `pentest.py` exercises tampering scenarios and writes a results document. |

## Requirements and setup

Use Python 3.8 or newer with SQLite support. The core CLI uses Python's standard
library. ReportLab is an optional dependency for the reporting module.

Run these commands from the repository root on macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python src/main.py
```

On Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python src/main.py
```

To install the optional PDF dependency in the activated environment:

```bash
python -m pip install reportlab
```

The application opens `src/octa_coc.db` and creates any missing tables and
triggers. A database file is already included in the repository, so launching
the application may open existing data.

## First walkthrough

1. Launch `python src/main.py` from the repository root.
2. Select **9 — Load sample data**. This adds users `U1`, `U2`, and `U3`, storage
   location `LOC-01`, and a sample file at
   `src/mock_evidence/sample_disk_image.txt`.
3. Select **8 — Open a case**. Use an unused case ID such as `CASE-DEMO-001`, a
   title, and `U1` as the lead investigator. Optional fields can be left blank.
4. Select **1 — Register new evidence**. Enter your case ID, an unused evidence
   ID such as `EV-DEMO-001`, the sample file path above, custodian `U1`, and
   location `LOC-01`.
5. Select **2 — Transfer custody**. Enter the evidence ID, state `In Transit`,
   releasing custodian `U1`, and receiving custodian `U2`.
6. Select **3 — View case audit trail** to inspect the recorded events.
7. Select **6 — Verify chain integrity** to check both the chain and its anchor
   records for that case.
8. Select **0 — Exit** when finished.

File paths entered into the menu are relative to the directory from which you
launched Python, unless you provide an absolute path. Sample data and records
created through the menu persist between runs.

## Custody lifecycle

New evidence starts in `Logged`. Use the exact state names shown below when
entering a transfer.

| Current state | Allowed next states |
| --- | --- |
| Logged | In Transit |
| In Transit | Under Analysis, Secured Storage |
| Under Analysis | Secured Storage, In Transit |
| Secured Storage | Disposed, In Transit |
| Disposed | None; this is a final state. |

A transfer requires two different registered user IDs, and the releasing user
must be the current custodian. The application derives the latest state and
custodian from custody history, with the registration audit entry providing
the initial custodian.

## Repository layout

```text
.
├── README.md                  Original project overview
├── README_DETAILED.md          Setup and usage guide
├── diagram/                   Entity relationship diagram
├── docs/
│   └── research/              Research documents
└── src/
    ├── main.py                Interactive terminal menu
    ├── database.py            SQLite schema, connection, and protective triggers
    ├── evidence.py            Evidence registration and lookup
    ├── coc_hash_chain.py      File hashing, audit chains, and anchor verification
    ├── state_machine.py       Custody transitions and transfer validation
    ├── alerts.py              Transit thresholds and access violation logging
    ├── reporting.py           PDF report generation and verification
    ├── pentest.py             Security demonstrations and results generation
    └── octa_coc.db             Local SQLite database
```

The database contains six main tables: `User`, `Case`, `Evidence`, `Location`,
`CustodyRecord`, and `AuditLog`.

Runtime files include `src/anchors/anchor_log.txt` for audit fingerprints,
`src/mock_evidence/` for menu-generated sample evidence, and `src/reports/` as
the reporting module's default output directory. Evidence registration reads
the source file and stores metadata and a hash; it does not archive a copy of
the evidence file.

## Module demonstrations

With the virtual environment activated, run these demonstrations individually
from the repository root:

```bash
python src/database.py
python src/evidence.py
python src/state_machine.py
python src/alerts.py
```

These demonstrations use in-memory databases; the evidence, custody, and alert
examples also create temporary files. Inspect their printed `PASS` or `FAIL`
results rather than relying solely on the process exit code.

The broader security demonstration is available with:

```bash
python src/pentest.py
```

It uses disposable databases and writes `src/PENTEST_RESULTS.md`. Some scenarios
also append to the default `src/anchors/anchor_log.txt`, so run it in a separate
project copy when preserving an existing application's anchor history matters.
The generated results describe the observed behavior of that run, including
any limitations or unexpectedly successful attacks.

## Current limitations

- The terminal application accepts user IDs without authenticating the people
  entering them. Checking two different IDs does not establish two independent
  approvals or verify digital signatures.
- Database triggers protect ordinary update and delete operations on the two
  protected tables. Someone controlling the database file can alter the schema
  or remove those triggers. The `Evidence` table has no equivalent triggers.
- The anchor log is a local file. Its usefulness as an independent integrity
  reference depends on protecting it separately from the database.
- Menu option **6** verifies audit records; it does not reread evidence files
  and compare their current contents against the registered hashes.
- Alert checks are callable functions, with no background scheduler or
  notification delivery configured. Reporting and alerts still need to be
  connected to their terminal menu actions.

## Further reading

- [Original project overview](README.md)
- [Source directory](src/)
- [Project documentation](docs/README.md)
- [Research materials](docs/research/)
- [Entity relationship diagram](diagram/Entity%20Relationship%20Diagram.jpeg)
