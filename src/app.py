"""
app.py - The OCTA-CoC menu, wrapped in a Streamlit page instead of a terminal.


Run it with:
    streamlit run app.py
"""

import tempfile
from pathlib import Path

import streamlit as st

import alerts
import coc_hash_chain as chain
import database
import evidence
import pentest
import reporting
import state_machine

st.set_page_config(page_title="OCTA-CoC", layout="wide")

PAGES = [
    "Register new evidence",
    "Transfer custody",
    "View case audit trail",
    "Generate compliance report",
    "Run threshold / alert check",
    "Verify chain integrity",
    "Add a user",
    "Open a case",
    "Load sample data",
    "Run pentest",
]


def save_upload(uploaded_file):
    """Save a Streamlit file upload to a temp path register_evidence can read."""
    temp_path = Path(tempfile.gettempdir()) / uploaded_file.name
    temp_path.write_bytes(uploaded_file.getvalue())
    return temp_path


# ---------------------------------------------------------------------------
# Pages - one function per menu item, same order as main.py
# ---------------------------------------------------------------------------

def page_register_evidence(conn):
    st.header("Register new evidence")
    with st.form("register_evidence"):
        case_id = st.text_input("Case ID")
        evidence_id = st.text_input("Evidence ID")
        uploaded_file = st.file_uploader("Evidence file")
        custodian_id = st.text_input("Your user ID (custodian)")
        location_id = st.text_input("Storage location ID (optional)")
        evidence_type = st.text_input("Evidence type, e.g. Disk image (optional)")
        device_type = st.text_input("Device type, e.g. Laptop (optional)")
        submitted = st.form_submit_button("Register")

    if not submitted:
        return
    if not uploaded_file:
        st.error("Choose an evidence file first")
        return
    try:
        file_path = save_upload(uploaded_file)
        fingerprint = evidence.register_evidence(
            conn, case_id, evidence_id, file_path, custodian_id,
            location_id=location_id or None, evidence_type=evidence_type or None,
            device_type=device_type or None)
        st.success(f"Registered {evidence_id} under {case_id}")
        st.code(f"SHA-256: {fingerprint}")
        st.caption("Audit entry written and anchored.")
    except (ValueError, RuntimeError) as error:
        st.error(str(error))


def page_transfer_custody(conn):
    st.header("Transfer custody")
    evidence_id = st.text_input("Evidence ID")
    if not evidence_id:
        return

    try:
        state, custodian = evidence.current_status(conn, evidence_id)
    except ValueError as error:
        st.error(str(error))
        return

    allowed = state_machine.allowed_next_states(state)
    st.write(f"**{evidence_id}** is currently **{state}**, held by **{custodian}**")
    if not allowed:
        st.warning("This state is final - the item cannot be moved again.")
        return
    st.write(f"It may move to: {', '.join(allowed)}")

    with st.form("transfer_custody"):
        new_state = st.selectbox("New state", allowed)
        from_user_id = st.text_input("Releasing custodian ID")
        to_user_id = st.text_input("Receiving custodian ID")
        reason = st.text_input("Reason for the transfer (optional)")
        submitted = st.form_submit_button("Transfer")

    if submitted:
        try:
            state_machine.transfer_custody(conn, evidence_id, new_state,
                                           from_user_id, to_user_id,
                                           reason=reason or None)
            st.success(f"{evidence_id} is now '{new_state}', held by {to_user_id}")
        except (ValueError, RuntimeError) as error:
            st.error(str(error))


def page_view_audit_trail(conn):
    st.header("View case audit trail")
    case_id = st.text_input("Case ID")
    if not case_id:
        return

    entries = chain.get_chain(conn, case_id)
    if not entries:
        st.info("This case has no audit entries yet.")
        return

    rows = [{
        "Sequence": entry["Sequence"],
        "Timestamp": entry["Timestamp"],
        "Result": entry["Result"],
        "Action": entry["ActionPerformed"],
        "User": entry["UserID"],
        "Evidence": entry["EvidenceID"],
        "Previous hash": entry["PreviousHash"][:16] + "...",
        "This hash": entry["EntryHash"][:16] + "...",
    } for entry in entries]
    st.dataframe(rows, use_container_width=True)


def page_generate_report(conn):
    st.header("Generate compliance report")
    case_id = st.text_input("Case ID")
    if st.button("Generate") and case_id:
        try:
            report_path = reporting.generate_report(conn, case_id)
            st.success(f"Report written to: {report_path}")
            st.caption("Its fingerprint has been recorded in the case's audit trail.")
            st.download_button("Download PDF", data=Path(report_path).read_bytes(),
                               file_name=Path(report_path).name, mime="application/pdf")
        except (ValueError, RuntimeError) as error:
            st.error(str(error))


def page_check_alerts(conn):
    st.header("Run threshold / alert check")
    hours_limit = st.number_input("Hours limit", min_value=1,
                                  value=alerts.DEFAULT_HOURS_LIMIT)
    if not st.button("Check"):
        return

    overdue = alerts.check_thresholds(conn, hours_limit=hours_limit)
    if not overdue:
        st.info(f"Nothing is overdue. No item has been '{alerts.WATCHED_STATE}'"
               f" for more than {hours_limit} hours.")
        return

    st.warning(f"{len(overdue)} item(s) have been '{alerts.WATCHED_STATE}'"
              f" for more than {hours_limit} hours:")
    st.dataframe(overdue, use_container_width=True)


def page_verify_chain(conn):
    st.header("Verify chain integrity")
    case_id = st.text_input("Case ID")
    if not st.button("Verify") or not case_id:
        return

    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    anchor_ok, anchor_message = chain.verify_against_anchor(conn, case_id)
    (st.success if chain_ok else st.error)(f"Chain check: {chain_message}")
    (st.success if anchor_ok else st.error)(f"Anchor check: {anchor_message}")


def page_add_user(conn):
    st.header("Add a user")
    with st.form("add_user"):
        user_id = st.text_input("User ID")
        full_name = st.text_input("Full name")
        role = st.text_input("Role, e.g. Investigator, Analyst, Evidence Custodian")
        email = st.text_input("Email (optional)")
        dept = st.text_input("Department (optional)")
        phone = st.text_input("Phone number (optional)")
        submitted = st.form_submit_button("Add user")

    if not submitted:
        return
    try:
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (user_id,)).fetchone() is not None:
            raise ValueError(f"User '{user_id}' already exists")
        conn.execute('INSERT INTO "User" (UserID, FullName, Email, Role, Dept, PhoneNo,'
                     ' Status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (user_id, full_name, email or None, role, dept or None,
                      phone or None, "Active"))
        conn.commit()
        st.success(f"Added {user_id} ({full_name}, {role})")
    except ValueError as error:
        st.error(str(error))


def page_open_case(conn):
    st.header("Open a case")
    with st.form("open_case"):
        case_id = st.text_input("Case ID")
        title = st.text_input("Case title")
        owner_id = st.text_input("Lead investigator's user ID")
        case_number = st.text_input("Case number (optional)")
        investigation_type = st.text_input("Investigation type (optional)")
        description = st.text_area("Description (optional)")
        submitted = st.form_submit_button("Open case")

    if not submitted:
        return
    try:
        if conn.execute('SELECT CaseID FROM "Case" WHERE CaseID = ?',
                        (case_id,)).fetchone() is not None:
            raise ValueError(f"Case '{case_id}' already exists")
        if conn.execute('SELECT UserID FROM "User" WHERE UserID = ?',
                        (owner_id,)).fetchone() is None:
            raise ValueError(f"User '{owner_id}' does not exist - add the user first")

        opened_at = chain.now_utc()
        conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, CaseNumber,'
                     ' CaseDescription, InvestigationType, DateOpened, Status)'
                     " VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')",
                     (case_id, owner_id, title, case_number or None,
                      description or None, investigation_type or None, opened_at))
        conn.commit()
        st.success(f"Opened {case_id} ({title})")
        st.code(f"Genesis hash: {chain.genesis_hash(case_id, opened_at)}")
    except ValueError as error:
        st.error(str(error))


def page_load_sample_data(conn):
    st.header("Load sample data")
    st.caption("Three users and one storage location, for a demo.")
    if not st.button("Load sample data"):
        return

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

    st.success("Sample data ready:")
    for user_id, name, role in users:
        st.write(f"- {user_id}  {name}  ({role})")
    st.write("- LOC-01  Evidence Room")
    st.write(f"- {sample_file}")
    st.caption("Next: open a case, then register evidence.")


def page_run_pentest():
    st.header("Run pentest")
    st.caption("Phase 8: attacks OCTA-CoC on purpose, using a fresh, throwaway"
              " database each time. Nothing here touches the real octa_coc.db.")
    if not st.button("Run pentest"):
        return

    passed = pentest.run_pentest()
    (st.success if passed else st.error)(
        "PASS - every attack was blocked, caught, or is a documented limitation"
        if passed else "FAIL - see the NOT BLOCKED row(s) below")

    rows = [{"Attack": a.title, "Outcome": a.outcome, "Detail": a.detail}
            for a in pentest.RESULTS]
    st.dataframe(rows, use_container_width=True)
    st.download_button("Download PENTEST_RESULTS.md",
                       data=pentest.RESULTS_FILE.read_text(),
                       file_name="PENTEST_RESULTS.md")


PAGE_FUNCTIONS = {
    "Register new evidence": page_register_evidence,
    "Transfer custody": page_transfer_custody,
    "View case audit trail": page_view_audit_trail,
    "Generate compliance report": page_generate_report,
    "Run threshold / alert check": page_check_alerts,
    "Verify chain integrity": page_verify_chain,
    "Add a user": page_add_user,
    "Open a case": page_open_case,
    "Load sample data": page_load_sample_data,
}


def main():
    st.sidebar.title("OCTA-CoC")
    st.sidebar.caption("Chain of Custody Tracker")
    choice = st.sidebar.radio("Menu", PAGES)

    try:
        conn = database.get_connection()
    except RuntimeError as error:
        st.error(f"Could not start: {error}")
        return
    st.sidebar.caption(f"Database: {database.DB_FILE}")

    if choice == "Run pentest":
        page_run_pentest()
    else:
        PAGE_FUNCTIONS[choice](conn)


if __name__ == "__main__":
    main()
