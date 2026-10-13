"""
reporting.py - The PDF compliance report.

generate_report() pulls everything recorded for a case and lays it out as a
PDF: the case details and genesis hash, whether the chain and the anchor
file are intact, every evidence item, every custody transfer, and the full
audit trail. Once the PDF is written, its own fingerprint is computed and
recorded as a new audit entry - so a later change to the PDF itself can be
detected, the same way a change to an evidence file can be.

ReportLab is only imported inside generate_report(), not at the top of the
file. That way the rest of OCTA-CoC still runs even on a computer where
ReportLab hasn't been installed yet - only option 4 in the menu needs it.

Run this file directly to build a sample report:
    python reporting.py
"""

import tempfile
from pathlib import Path

import coc_hash_chain as chain
import database
import evidence
import state_machine

REPORTS_DIR = Path(__file__).parent / "reports"


def _load_reportlab():
    """Import ReportLab, or raise a clear error if it isn't installed."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
        return colors, landscape(A4), mm, canvas
    except ImportError as error:
        raise RuntimeError(
            "ReportLab is not installed. Run:  pip install reportlab") from error


def _new_page(pdf, page_size, case_id, page_number):
    """Start a fresh page with a running header and footer."""
    width, height = page_size
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(20, height - 25, f"OCTA-CoC Compliance Report - {case_id}")
    pdf.setFont("Helvetica", 9)
    pdf.drawRightString(width - 20, height - 25, chain.now_utc())
    pdf.line(20, height - 32, width - 20, height - 32)

    pdf.setFont("Helvetica", 8)
    pdf.drawString(20, 15, "Octagon Cybersecurity Nig. Ltd. - Internal use only")
    pdf.drawRightString(width - 20, 15, f"Page {page_number}")
    return height - 50                                   # next free y position


def generate_report(conn, case_id, output_dir=REPORTS_DIR, anchor_file=chain.ANCHOR_FILE):
    """Build the PDF report for one case. Returns the file path."""
    colors, page_size, mm, canvas = _load_reportlab()
    width, height = page_size

    case = conn.execute('SELECT * FROM "Case" WHERE CaseID = ?', (case_id,)).fetchone()
    if case is None:
        raise ValueError(f"Case '{case_id}' does not exist")

    genesis = chain.genesis_hash(case_id, case["DateOpened"])
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    anchor_ok, anchor_message = chain.verify_against_anchor(conn, case_id, anchor_file)
    items = evidence.list_case_evidence(conn, case_id)
    entries = chain.get_chain(conn, case_id)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    final_path = output_dir / f"{case_id}_report.pdf"
    draft_path = output_dir / f".{case_id}_report.pdf.tmp"

    pdf = canvas.Canvas(str(draft_path), pagesize=page_size)
    page_number = 1
    y = _new_page(pdf, page_size, case_id, page_number)

    def need_room(lines_needed, line_height=14):
        """Start a new page if the next block won't fit above the footer."""
        nonlocal y, page_number
        if y - (lines_needed * line_height) < 35:
            pdf.showPage()
            page_number += 1
            y = _new_page(pdf, page_size, case_id, page_number)

    def heading(text):
        nonlocal y
        need_room(2)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(20, y, text)
        y -= 16

    def line(text, font="Helvetica", size=9, indent=20):
        nonlocal y
        need_room(1)
        pdf.setFont(font, size)
        pdf.drawString(indent, y, text)
        y -= 13

    # --- Case summary -------------------------------------------------------
    heading("Case summary")
    line(f"Case ID: {case['CaseID']}      Title: {case['CaseTitle']}")
    line(f"Opened: {case['DateOpened']}      Status: {case['Status']}")
    if case["CaseDescription"]:
        line(f"Description: {case['CaseDescription']}")
    line(f"Genesis hash: {genesis}", font="Courier", size=8)
    y -= 6

    # --- Integrity result -----------------------------------------------------
    heading("Integrity check")
    pdf.setFillColor(colors.HexColor("#1a7a4c") if chain_ok else colors.HexColor("#a8321f"))
    line(f"Chain check:  {'PASS' if chain_ok else 'FAIL'} - {chain_message}")
    pdf.setFillColor(colors.HexColor("#1a7a4c") if anchor_ok else colors.HexColor("#a8321f"))
    line(f"Anchor check: {'PASS' if anchor_ok else 'FAIL'} - {anchor_message}")
    pdf.setFillColor(colors.black)
    y -= 6

    # --- Evidence -------------------------------------------------------------
    heading(f"Evidence ({len(items)} item(s))")
    if not items:
        line("No evidence has been registered under this case.")
    for item in items:
        state, custodian = evidence.current_status(conn, item["EvidenceID"])
        line(f"{item['EvidenceID']}  -  {item['EvidenceName']}"
            f"  ({item['EvidenceType'] or 'type not recorded'})")
        line(f"    State: {state}     Held by: {custodian}", indent=30)
        line(f"    {item['HashAlgorithm']}: {item['HashValue']}",
            font="Courier", size=8, indent=30)
    y -= 6

    # --- Custody transfers ------------------------------------------------
    heading("Custody transfers")
    any_transfer = False
    for item in items:
        for record in state_machine.custody_history(conn, item["EvidenceID"]):
            any_transfer = True
            line(f"{item['EvidenceID']}: {record['FromUserID']} -> {record['ToUserID']}"
                f"  ->  {record['NewState']}   ({record['TransferDate']}"
                f" {record['TransferTime']})")
    if not any_transfer:
        line("No custody transfers have been recorded yet.")
    y -= 6

    # --- Audit trail ------------------------------------------------------
    heading(f"Full audit trail ({len(entries)} entries)")
    for entry in entries:
        line(f"#{entry['Sequence']}  [{entry['Result']}]  {entry['Timestamp']}"
            f"  {entry['ActionPerformed']}")
        line(f"    previous: {entry['PreviousHash']}", font="Courier", size=7, indent=30)
        line(f"    this    : {entry['EntryHash']}", font="Courier", size=7, indent=30)

    pdf.save()

    draft_path.replace(final_path)                        # only now is it final

    report_hash = chain.hash_file(final_path)
    chain.add_entry(conn, case_id,
                    f"Report generated: {final_path.name} (sha256: {report_hash})",
                    result="Success", anchor_file=anchor_file)

    return str(final_path)


def verify_report_file(conn, case_id, report_path, anchor_file=chain.ANCHOR_FILE):
    """Re-fingerprint a report PDF and check it against what was recorded."""
    current = chain.hash_file(report_path)
    for entry in reversed(chain.get_chain(conn, case_id)):
        if entry["ActionPerformed"].startswith("Report generated:") and current in entry[
                "ActionPerformed"]:
            return True, "Report matches the fingerprint recorded when it was generated"
    return False, "No matching report fingerprint found in the audit trail"


# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

def demo_generate_report():
    """Build a small case, generate its report, and check the report's own hash."""
    demo_anchor = Path(tempfile.gettempdir()) / "octa_coc_demo_anchor.txt"
    demo_anchor.unlink(missing_ok=True)
    conn = database.get_connection(":memory:")
    case_id = "CASE-001"

    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U1', 'Officer A', 'Investigator')")
    conn.execute('INSERT INTO "User" (UserID, FullName, Role)'
                 " VALUES ('U2', 'Officer B', 'Analyst')")
    conn.execute('INSERT INTO "Case" (CaseID, UserID, CaseTitle, CaseDescription,'
                 " DateOpened, Status) VALUES (?, 'U1', 'Laptop theft',"
                 " 'Stolen company laptop', ?, 'Open')", (case_id, chain.now_utc()))
    conn.commit()

    sample = Path(tempfile.gettempdir()) / "octa_coc_sample_evidence.txt"
    sample.write_text("Contents of the seized laptop image")
    evidence.register_evidence(conn, case_id, "EV-001", sample, "U1",
                               evidence_type="Disk image", device_type="Laptop",
                               anchor_file=demo_anchor)
    state_machine.transfer_custody(conn, "EV-001", "In Transit", "U1", "U2",
                                   anchor_file=demo_anchor)
    sample.unlink(missing_ok=True)

    print("1. GENERATING THE REPORT\n")
    try:
        report_path = generate_report(conn, case_id, output_dir=Path(tempfile.gettempdir()),
                                      anchor_file=demo_anchor)
    except RuntimeError as error:
        print(f"  {error}")
        conn.close()
        demo_anchor.unlink(missing_ok=True)
        return False

    print(f"  Written to: {report_path}\n")

    print("2. THE REPORT'S OWN FINGERPRINT WAS RECORDED\n")
    report_ok, report_message = verify_report_file(conn, case_id, report_path, demo_anchor)
    print(f"  {report_message}\n")

    print("3. CHAIN STILL VERIFIES\n")
    chain_ok, chain_message = chain.verify_chain(conn, case_id)
    print(f"  {chain_message}")

    conn.close()
    demo_anchor.unlink(missing_ok=True)
    Path(report_path).unlink(missing_ok=True)
    passed = report_ok and chain_ok
    print("\nResult:", "PASS - the report was built and its fingerprint checks out"
          if passed else "FAIL - something did not behave as expected")
    return passed


if __name__ == "__main__":
    demo_generate_report()