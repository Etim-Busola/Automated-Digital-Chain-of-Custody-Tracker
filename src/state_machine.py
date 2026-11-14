"""
state_machine.py - Custody transfers, and the rules that control them.

A transfer is only written if it passes every check:
  * the new state is one the item is allowed to move to,
  * two different custodian IDs are given (dual authorisation),
  * both of them are real users,
  * the person releasing the item is the one currently holding it.

A rejected attempt is not silently dropped - it is written into the audit
chain with Result = 'Rejected', so the record shows what was attempted as
well as what succeeded.

Run this file directly to see valid and invalid transfers:
    python state_machine.py
"""

import sqlite3
import tempfile
from pathlib import Path

import coc_hash_chain as chain
import database
import evidence

# The only moves allowed. Anything not listed here is refused.
TRANSITIONS = {
    "Logged": ["In Transit"],
    "In Transit": ["Under Analysis", "Secured Storage"],
    "Under Analysis": ["Secured Storage", "In Transit"],
    "Secured Storage": ["Disposed", "In Transit"],
    "Disposed": [],
}


def allowed_next_states(state):
    """Return the states an item in this state may move to."""
    return TRANSITIONS.get(state, [])


def record_rejected_attempt(conn, case_id, user_id, evidence_id, reason,
                            anchor_file=chain.ANCHOR_FILE):
    """Write a refused attempt into the audit chain."""
    chain.add_entry(conn, case_id, f"Transfer refused: {reason}", user_id,
                    evidence_id, result="Rejected", anchor_file=anchor_file)


def transfer_custody(conn, evidence_id, new_state, from_user_id, to_user_id,
                     reason=None, signature=None, anchor_file=chain.ANCHOR_FILE):
    """Hand an item from one custodian to another. Returns the new state."""
    item = evidence.get_evidence(conn, evidence_id)      # raises if unknown
    case_id = item["CaseID"]
    state, custodian = evidence.current_status(conn, evidence_id)

    def refuse(message):
        record_rejected_attempt(conn, case_id, from_user_id, evidence_id,
                                message, anchor_file)
        raise ValueError(message)

    if new_state not in TRANSITIONS:
        refuse(f"'{new_state}' is not a known state")

    if not from_user_id or not to_user_id:
        refuse("Two custodian IDs are required (dual authorisation)")

    if from_user_id == to_user_id:
        refuse("The two custodian IDs must be different people")

    for user_id in (from_user_id, to_user_id):
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (user_id,)).fetchone() is None:
            refuse(f"User '{user_id}' does not exist")

    if new_state not in allowed_next_states(state):
        allowed = ", ".join(allowed_next_states(state)) or "nothing - this state is final"
        refuse(f"'{state}' cannot move to '{new_state}'. Allowed: {allowed}")

    if custodian is not None and from_user_id != custodian:
        refuse(f"'{from_user_id}' does not hold this item - '{custodian}' does")

    now = chain.now_utc()
    try:
        conn.execute(
            "INSERT INTO CustodyRecord (EvidenceID, FromUserID, ToUserID, NewState,"
            " TransferDate, TransferTime, TransferReason, Signature,"
            " VerificationStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, from_user_id, to_user_id, new_state,
             now[:10], now[11:19], reason, signature, "Verified"))
        conn.commit()
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not save the custody record: {error}") from error

    chain.add_entry(conn, case_id,
                    f"Custody transferred to {new_state}", to_user_id, evidence_id,
                    anchor_file=anchor_file)
    return new_state


def request_transfer(conn, evidence_id, new_state, from_user_id, to_user_id,
                     reason=None, anchor_file=chain.ANCHOR_FILE):
    """Ask for a custody transfer. Returns the new PendingTransfer's id.

    This runs the same checks as transfer_custody(), but instead of moving
    the item immediately, it waits for the receiving custodian to approve
    or reject it (see approve_transfer / reject_transfer below).
    """
    item = evidence.get_evidence(conn, evidence_id)      # raises if unknown
    case_id = item["CaseID"]
    state, custodian = evidence.current_status(conn, evidence_id)

    def refuse(message):
        record_rejected_attempt(conn, case_id, from_user_id, evidence_id,
                                message, anchor_file)
        raise ValueError(message)

    already_pending = conn.execute(
        "SELECT PendingID FROM PendingTransfer WHERE EvidenceID = ? AND Status = 'Pending'",
        (evidence_id,)).fetchone()
    if already_pending is not None:
        refuse(f"A transfer for '{evidence_id}' is already pending approval")

    if new_state not in TRANSITIONS:
        refuse(f"'{new_state}' is not a known state")

    if not from_user_id or not to_user_id:
        refuse("Two custodian IDs are required (dual authorisation)")

    if from_user_id == to_user_id:
        refuse("The two custodian IDs must be different people")

    for user_id in (from_user_id, to_user_id):
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (user_id,)).fetchone() is None:
            refuse(f"User '{user_id}' does not exist")

    if new_state not in allowed_next_states(state):
        allowed = ", ".join(allowed_next_states(state)) or "nothing - this state is final"
        refuse(f"'{state}' cannot move to '{new_state}'. Allowed: {allowed}")

    if custodian is not None and from_user_id != custodian:
        refuse(f"'{from_user_id}' does not hold this item - '{custodian}' does")

    requested_at = chain.now_utc()
    try:
        cursor = conn.execute(
            "INSERT INTO PendingTransfer (EvidenceID, FromUserID, ToUserID, NewState,"
            " Reason, RequestedAt, Status) VALUES (?, ?, ?, ?, ?, ?, 'Pending')",
            (evidence_id, from_user_id, to_user_id, new_state, reason, requested_at))
        conn.commit()
    except sqlite3.Error as error:
        raise RuntimeError(f"Could not save the pending transfer: {error}") from error

    chain.add_entry(conn, case_id, f"Transfer requested: {state} -> {new_state}",
                    from_user_id, evidence_id, result="Pending", anchor_file=anchor_file)
    return cursor.lastrowid


def get_pending_transfer(conn, pending_id):
    """Return one pending transfer row, or raise if it does not exist."""
    row = conn.execute("SELECT * FROM PendingTransfer WHERE PendingID = ?",
                       (pending_id,)).fetchone()
    if row is None:
        raise ValueError(f"Pending transfer #{pending_id} does not exist")
    return row


def list_pending_for_user(conn, user_id):
    """Return every pending transfer request awaiting this user's approval."""
    return conn.execute(
        "SELECT * FROM PendingTransfer WHERE ToUserID = ? AND Status = 'Pending'"
        " ORDER BY RequestedAt", (user_id,)).fetchall()


def approve_transfer(conn, pending_id, approving_user_id, anchor_file=chain.ANCHOR_FILE):
    """The receiving custodian accepts a pending transfer. Returns the new state."""
    pending = get_pending_transfer(conn, pending_id)
    if pending["Status"] != "Pending":
        raise ValueError(f"Pending transfer #{pending_id} is already {pending['Status'].lower()}")
    if approving_user_id != pending["ToUserID"]:
        raise ValueError(f"Only '{pending['ToUserID']}' can approve this transfer")

    new_state = transfer_custody(conn, pending["EvidenceID"], pending["NewState"],
                                 pending["FromUserID"], pending["ToUserID"],
                                 reason=pending["Reason"], anchor_file=anchor_file)
    conn.execute("UPDATE PendingTransfer SET Status = 'Approved' WHERE PendingID = ?",
                (pending_id,))
    conn.commit()
    return new_state


def reject_transfer(conn, pending_id, rejecting_user_id, reason=None,
                    anchor_file=chain.ANCHOR_FILE):
    """The receiving custodian declines a pending transfer. The item does not move."""
    pending = get_pending_transfer(conn, pending_id)
    if pending["Status"] != "Pending":
        raise ValueError(f"Pending transfer #{pending_id} is already {pending['Status'].lower()}")
    if rejecting_user_id != pending["ToUserID"]:
        raise ValueError(f"Only '{pending['ToUserID']}' can reject this transfer")

    conn.execute("UPDATE PendingTransfer SET Status = 'Rejected' WHERE PendingID = ?",
                (pending_id,))
    conn.commit()

    case_id = evidence.get_evidence(conn, pending["EvidenceID"])["CaseID"]
    detail = f"Transfer request to {pending['NewState']} rejected"
    if reason:
        detail += f": {reason}"
    chain.add_entry(conn, case_id, detail, rejecting_user_id, pending["EvidenceID"],
                    result="Rejected", anchor_file=anchor_file)


def custody_history(conn, evidence_id):
    """Return every handover of one item, oldest first."""
    return conn.execute("SELECT * FROM CustodyRecord WHERE EvidenceID = ?"
                        " ORDER BY CustodyID", (evidence_id,)).fetchall()


# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

def try_transfer(conn, evidence_id, new_state, from_user, to_user, anchor_file):
    """Attempt one transfer and print whether it was allowed or refused."""
    try:
        transfer_custody(conn, evidence_id, new_state, from_user, to_user,
                         reason="Demo transfer", anchor_file=anchor_file)
        print(f"  ALLOWED   {from_user} -> {to_user}, new state '{new_state}'")
        return True
    except ValueError as error:
        print(f"  REFUSED   {from_user} -> {to_user}, new state '{new_state}'")
        print(f"            -> {error}")
        return False


def demo_state_machine():
    """Show two valid transfers, then every kind of invalid one."""
    demo_anchor = Path(tempfile.gettempdir()) / "octa_coc_demo_anchor.txt"
    demo_anchor.unlink(missing_ok=True)
    conn = database.get_connection(":memory:")
    case_id = "CASE-001"

    for user_id, name, role in (("U1", "Officer A", "Investigator"),
                                ("U2", "Officer B", "Analyst"),
                                ("U3", "Officer C", "Evidence Custodian")):
        conn.execute('INSERT INTO "User" (UserID, FullName, Role) VALUES (?, ?, ?)',
                     (user_id, name, role))
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, DateOpened, Status)'
                 " VALUES (?, 'U1', 'Laptop theft', ?, 'Open')",
                 (case_id, chain.now_utc()))
    conn.commit()

    sample = Path(tempfile.gettempdir()) / "octa_coc_seized_laptop.img"
    sample.write_text("Contents of the seized laptop image")
    evidence.register_evidence(conn, case_id, "EV-001", sample, "U1",
                               anchor_file=demo_anchor)
    sample.unlink(missing_ok=True)

    print("The allowed moves\n")
    for state, next_states in TRANSITIONS.items():
        print(f"  {state:<16} -> {', '.join(next_states) or 'nothing (final state)'}")
    print()

    state, custodian = evidence.current_status(conn, "EV-001")
    print(f"EV-001 starts as '{state}', held by {custodian}.\n")

    print("1. VALID TRANSFERS\n")
    good = [try_transfer(conn, "EV-001", "In Transit", "U1", "U2", demo_anchor),
            try_transfer(conn, "EV-001", "Under Analysis", "U2", "U3", demo_anchor)]
    print()

    print("2. TRANSFERS THAT MUST BE REFUSED\n")
    bad = [try_transfer(conn, "EV-001", "Disposed", "U3", "U1", demo_anchor),
           try_transfer(conn, "EV-001", "Lost", "U3", "U1", demo_anchor),
           try_transfer(conn, "EV-001", "Secured Storage", "U3", "U3", demo_anchor),
           try_transfer(conn, "EV-001", "Secured Storage", "U1", "U2", demo_anchor),
           try_transfer(conn, "EV-001", "Secured Storage", "U3", "U9", demo_anchor)]
    print()

    print("3. THE CUSTODY TRAIL\n")
    for record in custody_history(conn, "EV-001"):
        print(f"  #{record['CustodyID']}  {record['FromUserID']} -> {record['ToUserID']}"
              f"   {record['NewState']:<16} {record['TransferDate']} {record['TransferTime']}")
    state, custodian = evidence.current_status(conn, "EV-001")
    print(f"\n  Now: '{state}', held by {custodian}\n")

    print("4. THE AUDIT CHAIN (refused attempts are recorded too)\n")
    for entry in chain.get_chain(conn, case_id):
        print(f"  #{entry['Sequence']}  {entry['Result']:<8} {entry['ActionPerformed']}")
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    print(f"\n  Chain check : {chain_message}")

    conn.close()
    demo_anchor.unlink(missing_ok=True)
    passed = all(good) and not any(bad) and chain_ok
    print("\nResult:", "PASS - only permitted, dual-authorised transfers were written"
          if passed else "FAIL - something did not behave as expected")
    return passed


if __name__ == "__main__":
    demo_state_machine()
