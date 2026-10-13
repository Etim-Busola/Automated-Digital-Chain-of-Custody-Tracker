"""
alerts.py - Flags evidence that has been In Transit too long, and records
unauthorised access attempts.

check_thresholds() looks for items whose latest custody record left them
'In Transit' more than a set number of hours ago. In Transit is the state
where evidence is most exposed - not locked in storage, not on an analyst's
bench, just in someone's hands while it is moved - so a long delay is worth
flagging.

log_access_violation() writes a permanent audit entry for an unauthorised
attempt. state_machine.py already does this automatically whenever a
transfer is refused; this function exists so the same thing can also be
logged directly, e.g. a failed login or someone trying to open a case they
have no business in.

Run this file directly to see an overdue item get flagged:
    python alerts.py
"""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import coc_hash_chain as chain
import database
import evidence
import state_machine

DEFAULT_HOURS_LIMIT = 48
WATCHED_STATE = "In Transit"


def check_thresholds(conn, hours_limit=DEFAULT_HOURS_LIMIT, now=None):
    """Return every item stuck 'In Transit' past hours_limit.

    now lets a test (or a demo) check against a future point in time,
    instead of having to back-date real records.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=hours_limit)

    overdue = []
    for item in conn.execute("SELECT EvidenceID, CaseID FROM Evidence"
                             " ORDER BY EvidenceID").fetchall():
        last = conn.execute(
            "SELECT NewState, ToUserID, TransferDate, TransferTime"
            " FROM CustodyRecord WHERE EvidenceID = ?"
            " ORDER BY CustodyID DESC LIMIT 1", (item["EvidenceID"],)).fetchone()
        if last is None or last["NewState"] != WATCHED_STATE:
            continue

        moved_at = datetime.fromisoformat(
            f"{last['TransferDate']}T{last['TransferTime']}+00:00")
        if moved_at > cutoff:
            continue

        hours_elapsed = (now - moved_at).total_seconds() / 3600
        overdue.append({
            "EvidenceID": item["EvidenceID"],
            "CaseID": item["CaseID"],
            "Custodian": last["ToUserID"],
            "InTransitSince": f"{last['TransferDate']} {last['TransferTime']}",
            "HoursElapsed": round(hours_elapsed, 1),
        })
    return overdue


def log_access_violation(conn, user_id, evidence_id, reason="Unauthorised access attempt",
                         anchor_file=chain.ANCHOR_FILE):
    """Write a permanent audit entry recording an unauthorised attempt.

    The attempt is logged even if user_id isn't a real, registered user -
    that is usually exactly what an access violation looks like. AuditLog's
    UserID column only accepts known users (it has a foreign key to User),
    so an unrecognised ID is kept in the entry's text instead.
    """
    item = conn.execute("SELECT CaseID FROM Evidence WHERE EvidenceID = ?",
                        (evidence_id,)).fetchone()
    if item is None:
        raise ValueError(f"Evidence '{evidence_id}' does not exist")

    is_known_user = conn.execute('SELECT 1 FROM "User" WHERE UserID = ?',
                                 (user_id,)).fetchone() is not None
    logged_user = user_id if is_known_user else None
    detail = reason if is_known_user else f"{reason} (attempted ID: {user_id})"

    chain.add_entry(conn, item["CaseID"], f"Access violation: {detail}", logged_user,
                    evidence_id, result="Rejected", anchor_file=anchor_file)


# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

def demo_alerts():
    """Put an item In Transit, then check the threshold before and after it's due."""
    demo_anchor = Path(tempfile.gettempdir()) / "octa_coc_demo_anchor.txt"
    demo_anchor.unlink(missing_ok=True)
    conn = database.get_connection(":memory:")
    case_id = "CASE-001"

    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U1', 'Officer A', 'Investigator')")
    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U2', 'Officer B', 'Analyst')")
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, DateOpened, Status)'
                 " VALUES (?, 'U1', 'Laptop theft', ?, 'Open')", (case_id, chain.now_utc()))
    conn.commit()

    sample = Path(tempfile.gettempdir()) / "octa_coc_sample_evidence.txt"
    sample.write_text("Sample evidence for the alerts demo")
    evidence.register_evidence(conn, case_id, "EV-001", sample, "U1",
                               anchor_file=demo_anchor)
    sample.unlink(missing_ok=True)

    print("1. EVIDENCE GOES IN TRANSIT\n")
    state_machine.transfer_custody(conn, "EV-001", "In Transit", "U1", "U2",
                                   anchor_file=demo_anchor)
    print("  EV-001 is now 'In Transit', held by U2.\n")

    now = datetime.now(timezone.utc)

    print(f"2. CHECKING BEFORE THE {DEFAULT_HOURS_LIMIT}-HOUR LIMIT\n")
    early = check_thresholds(conn, now=now + timedelta(hours=47))
    print(f"  47 hours later - flagged items: {len(early)}\n")

    print(f"3. CHECKING AFTER THE {DEFAULT_HOURS_LIMIT}-HOUR LIMIT\n")
    late = check_thresholds(conn, now=now + timedelta(hours=49))
    for row in late:
        print(f"  OVERDUE  {row['EvidenceID']}  (case {row['CaseID']})")
        print(f"           held by {row['Custodian']}, in transit since"
              f" {row['InTransitSince']}")
        print(f"           {row['HoursElapsed']} hours elapsed"
              f" (limit is {DEFAULT_HOURS_LIMIT})\n")

    print("4. AN UNAUTHORISED ACCESS ATTEMPT IS LOGGED\n")
    log_access_violation(conn, "U9", "EV-001", "Tried to view a case with no assignment",
                         anchor_file=demo_anchor)
    last_entry = chain.get_chain(conn, case_id)[-1]
    print(f"  #{last_entry['Sequence']}  [{last_entry['Result']}]"
          f"  {last_entry['ActionPerformed']}")
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    print(f"\n  Chain check : {chain_message}")

    conn.close()
    demo_anchor.unlink(missing_ok=True)
    passed = len(early) == 0 and len(late) == 1 and chain_ok
    print("\nResult:", "PASS - the threshold and the violation log both worked"
          if passed else "FAIL - something did not behave as expected")
    return passed


if __name__ == "__main__":
    demo_alerts()