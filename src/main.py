"""
main.py - The terminal menu for OCTA-CoC.

This file holds no business logic. It asks the questions, calls the functions
in the other modules, and prints the answers. Every action is wrapped in error
handling, so a wrong file name or a refused transfer prints a clear message
and returns to the menu instead of crashing.

Run it with:
    python main.py
"""

import sqlite3
import sys
from pathlib import Path
import alerts
import coc_hash_chain as chain
import database
import evidence
import reporting
import state_machine

MENU = """
==================================================
  OCTA-CoC  -  Chain of Custody Tracker
==================================================
  1. Add a user
  2. Open a case
  3. Register new evidence
  4. Request custody transfer
  5. Approve / reject a pending transfer
  6. View case audit trail
  7. Verify chain integrity
  8. Run threshold / alert check
  9. Generate compliance report
 10. Load sample data (for a demo)
  0. Exit
"""


def ask(question, required=True):
    """Ask one question. An empty answer to a required question cancels."""
    answer = input(f"  {question}: ").strip()
    if required and not answer:
        raise ValueError("Cancelled - nothing was entered")
    return answer or None


# ---------------------------------------------------------------------------
# Menu actions
# ---------------------------------------------------------------------------

def action_register_evidence(conn):
    """3. Register new evidence."""
    case_id = ask("Case ID")
    file_path = ask("Path to the evidence file"
                   f" (accepted: {', '.join(sorted(evidence.ALLOWED_EXTENSIONS))};"
                   f" max {evidence.MAX_FILE_SIZE // (1024 * 1024)} MB)")
    custodian_id = ask("Your user ID (custodian)")
    location_id = ask("Storage location ID", required=False)
    evidence_type = ask("Evidence type (e.g. Disk image)", required=False)
    device_type = ask("Device type (e.g. Laptop)", required=False)

    evidence_id = database.next_id(conn, "Evidence", "EvidenceID", "EV-")
    fingerprint = evidence.register_evidence(
        conn, case_id, evidence_id, file_path, custodian_id,
        location_id=location_id, evidence_type=evidence_type,
        device_type=device_type)

    print(f"\n  Registered {evidence_id} under {case_id}")
    print(f"  SHA-256: {fingerprint}")
    print("  Audit entry written and anchored.")


def action_transfer_custody(conn):
    """4. Request a custody transfer."""
    evidence_id = ask("Evidence ID")
    state, custodian = evidence.current_status(conn, evidence_id)
    allowed = state_machine.allowed_next_states(state)

    print(f"\n  {evidence_id} is currently '{state}', held by {custodian}")
    if not allowed:
        print("  This state is final - the item cannot be moved again.\n")
        return
    print(f"  It may move to: {', '.join(allowed)}\n")

    new_state = ask("New state")
    from_user_id = ask("Releasing custodian ID")
    to_user_id = ask("Receiving custodian ID")
    reason = ask("Reason for the transfer", required=False)

    state_machine.request_transfer(conn, evidence_id, new_state,
                                   from_user_id, to_user_id, reason=reason)
    print(f"\n  Requested: {evidence_id} -> '{new_state}'."
         f" Waiting for {to_user_id} to approve (option 5).")


def action_view_audit_trail(conn):
    """6. View case audit trail."""
    case_id = ask("Case ID")
    entries = chain.get_chain(conn, case_id)
    if not entries:
        print("\n  This case has no audit entries yet.\n")
        return

    print(f"\n  Audit trail for {case_id}\n")
    for entry in entries:
        print(f"  #{entry['Sequence']}  {entry['Timestamp']}  [{entry['Result']}]")
        print(f"      {entry['ActionPerformed']}")
        print(f"      user: {entry['UserID']}   evidence: {entry['EvidenceID']}")
        print(f"      previous: {entry['PreviousHash'][:16]}...")
        print(f"      this    : {entry['EntryHash'][:16]}...\n")


def action_generate_report(conn):
    """9. Generate compliance report."""
    case_id = ask("Case ID")
    report_path = reporting.generate_report(conn, case_id)
    print(f"\n  Report written to: {report_path}")
    print("  Its fingerprint has been recorded in the case's audit trail.\n")


def action_check_alerts(conn):
    """8. Run threshold / alert check."""
    hours_text = ask(f"Hours limit (blank for {alerts.DEFAULT_HOURS_LIMIT})",
                     required=False)
    hours_limit = int(hours_text) if hours_text else alerts.DEFAULT_HOURS_LIMIT

    overdue = alerts.check_thresholds(conn, hours_limit=hours_limit)
    if not overdue:
        print(f"\n  Nothing is overdue. No item has been '{alerts.WATCHED_STATE}'"
              f" for more than {hours_limit} hours.\n")
        return

    print(f"\n  {len(overdue)} item(s) have been '{alerts.WATCHED_STATE}'"
          f" for more than {hours_limit} hours:\n")
    for row in overdue:
        print(f"    {row['EvidenceID']}  (case {row['CaseID']})")
        print(f"      held by {row['Custodian']}, in transit since"
              f" {row['InTransitSince']}  -  {row['HoursElapsed']} hours\n")


def action_verify_chain(conn):
    """7. Verify chain integrity."""
    case_id = ask("Case ID")
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    anchor_ok, anchor_message = chain.verify_against_anchor(conn, case_id)
    print(f"\n  Chain check  : {'PASS' if chain_ok else 'FAIL'} - {chain_message}")
    print(f"  Anchor check : {'PASS' if anchor_ok else 'FAIL'} - {anchor_message}\n")


def action_add_user(conn):
    """1. Add a user."""
    full_name = ask("Full name")
    role = ask("Role (e.g. Investigator, Analyst, Evidence Custodian)")
    email = ask("Email", required=False)
    dept = ask("Department", required=False)
    phone = ask("Phone number", required=False)

    user_id = database.next_id(conn, "User", "UserID", "U", width=0)
    conn.execute('INSERT INTO "User" (UserID, FullName, Email, Role, Dept, PhoneNo,'
                 ' Status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (user_id, full_name, email, role, dept, phone, "Active"))
    conn.commit()
    print(f"\n  Added {user_id} ({full_name}, {role})\n")


def action_open_case(conn):
    """2. Open a case."""
    title = ask("Case title")
    owner_id = ask("Lead investigator's user ID")
    case_number = ask("Case number", required=False)
    investigation_type = ask("Investigation type", required=False)
    description = ask("Description", required=False)

    if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                    (owner_id,)).fetchone() is None:
        raise ValueError(f"User '{owner_id}' does not exist - add the user first")

    case_id = database.next_id(conn, "Case", "CaseID", "CASE-")
    opened_at = chain.now_utc()
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, CaseNumber,'
                 ' CaseDescription, InvestigationType, DateOpened, Status)'
                 " VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')",
                 (case_id, owner_id, title, case_number, description,
                  investigation_type, opened_at))
    conn.commit()
    print(f"\n  Opened {case_id} ({title})")
    print(f"  Genesis hash: {chain.genesis_hash(case_id, opened_at)}\n")


def action_load_sample_data(conn):
    """10. Load sample data, so a demo can start straight away."""
    users = [("U1", "Officer A", "Investigator"),
             ("U2", "Officer B", "Analyst"),
             ("U3", "Officer C", "Evidence Custodian")]
    for user_id, name, role in users:
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (user_id,)).fetchone() is None:
            conn.execute('INSERT INTO "User" (UserID, FullName, Role, Status)'
                         " VALUES (?, ?, ?, 'Active')", (user_id, name, role))

    if conn.execute("SELECT LocationID FROM Location WHERE LocationID = 'LOC-01'"
                    ).fetchone() is None:
        conn.execute("INSERT INTO Location (LocationID, LocationName, RoomNumber,"
                     " StorageType) VALUES ('LOC-01', 'Evidence Room', 'R3', 'Safe')")
    conn.commit()

    sample_folder = Path(__file__).parent / "mock_evidence"
    sample_folder.mkdir(exist_ok=True)
    sample_file = sample_folder / "sample_disk_image.txt"
    if not sample_file.exists():
        sample_file.write_text("Sample evidence file for OCTA-CoC demonstrations.\n")

    print("\n  Sample data ready:")
    for user_id, name, role in users:
        print(f"    {user_id}  {name}  ({role})")
    print("    LOC-01  Evidence Room")
    print(f"    {sample_file}")
    print("\n  Next: open a case (2), then register evidence (3).\n")


def action_approve_reject_transfer(conn):
    """5. Approve or reject a pending transfer."""
    user_id = ask("Your user ID")
    pending = state_machine.list_pending_for_user(conn, user_id)
    if not pending:
        print(f"\n  Nothing is waiting for {user_id}'s approval.\n")
        return

    print(f"\n  Pending transfers for {user_id}:\n")
    for row in pending:
        print(f"    #{row['PendingID']}  {row['EvidenceID']}  {row['FromUserID']} -> {user_id}"
             f"  ->  {row['NewState']}   (requested {row['RequestedAt']})")
        if row["Reason"]:
            print(f"        reason: {row['Reason']}")
    print()

    pending_id = int(ask("Pending transfer # to act on"))
    decision = ask("Approve or reject? (a/r)")

    if decision.lower().startswith("a"):
        new_state = state_machine.approve_transfer(conn, pending_id, user_id)
        print(f"\n  Approved - item is now '{new_state}'\n")
    else:
        reject_reason = ask("Reason for rejecting", required=False)
        state_machine.reject_transfer(conn, pending_id, user_id, reason=reject_reason)
        print("\n  Rejected.\n")


ACTIONS = {
    "1": action_add_user,
    "2": action_open_case,
    "3": action_register_evidence,
    "4": action_transfer_custody,
    "5": action_approve_reject_transfer,
    "6": action_view_audit_trail,
    "7": action_verify_chain,
    "8": action_check_alerts,
    "9": action_generate_report,
    "10": action_load_sample_data,
}


# ---------------------------------------------------------------------------
# The menu loop
# ---------------------------------------------------------------------------

def run_action(conn, choice):
    """Run one menu action and turn any problem into a readable message."""
    try:
        ACTIONS[choice](conn)
    except (ValueError, RuntimeError) as error:
        print(f"\n  Error: {error}\n")
    except sqlite3.Error as error:
        print(f"\n  Database error: {error}\n")
    except KeyboardInterrupt:
        print("\n\n  Cancelled.\n")
    except Exception as error:                      # never crash the menu
        print(f"\n  Unexpected error: {type(error).__name__}: {error}\n")


def main():
    """Open the database and run the menu until the user exits."""
    try:
        conn = database.get_connection()
    except RuntimeError as error:
        print(f"Could not start: {error}")
        return 1

    print(f"\nDatabase: {database.DB_FILE}")
    while True:
        print(MENU)
        try:
            choice = input("  Choose an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if choice == "0":
            print("\nGoodbye.")
            break
        if choice in ACTIONS:
            run_action(conn, choice)
        else:
            print("\n  Please choose a number from the menu.\n")

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
