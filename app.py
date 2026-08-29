import logging

import pandas as pd
import streamlit as st

from config.safety import validate_authorized_target
from database.db import (
    add_finding,
    add_report,
    add_scan,
    add_target,
    init_db,
    list_findings_for_scan,
    list_scans,
    list_targets,
    remove_target,
)
from modules.port_scanner import run_port_scan
from modules.reconnaissance import run_reconnaissance
from modules.reporting import DISCLAIMER, generate_html_report
from modules.risk_scoring import severity_distribution
from modules.vulnerability_assessment import build_assessment
from modules.web_checks import run_web_checks

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")


def run_scan(target_row: dict, intensity: str) -> tuple[int, dict, list[dict]]:
    target = target_row["target"]
    recon = run_reconnaissance(target=target)
    ports = run_port_scan(target=target, intensity=intensity)
    web_findings = run_web_checks(target=target)
    findings = build_assessment(target=target, recon=recon, port_scan=ports, web_findings=web_findings)
    summary = {"recon": recon, "ports": ports}
    scan_id = add_scan(target_id=target_row["id"], status="completed", scan_intensity=intensity, summary=summary)
    for finding in findings:
        add_finding(scan_id, finding)
    return scan_id, summary, findings


def dashboard():
    st.set_page_config(page_title="Ethical Hacking Assessment System", layout="wide")
    init_db()
    st.title("Ethical Hacking & Vulnerability Assessment System")
    st.error("AUTHORIZED SECURITY TESTING ONLY")
    st.caption(DISCLAIMER)

    st.sidebar.header("Target Management")
    with st.sidebar.form("add_target_form"):
        raw_target = st.text_input("Target (domain/IP)")
        explicit_auth = st.checkbox("I confirm I have explicit authorization to test this target")
        auth_note = st.text_input("Authorization note (ticket, owner approval, lab scope)")
        submitted = st.form_submit_button("Add Target")
        if submitted:
            try:
                target, authorized = validate_authorized_target(raw_target, explicit_auth)
                add_target(target, authorized, auth_note)
                st.sidebar.success("Target added.")
            except Exception as exc:
                st.sidebar.error(str(exc))

    targets = list_targets()
    if targets:
        target_labels = {f"{row['id']} - {row['target']}": row for row in targets}
        remove_label = st.sidebar.selectbox("Remove target", options=[""] + list(target_labels.keys()))
        if st.sidebar.button("Delete Selected Target") and remove_label:
            remove_target(target_labels[remove_label]["id"])
            st.sidebar.success("Target removed.")
            st.rerun()

    st.header("Scan Execution")
    if not targets:
        st.info("Add a target to begin.")
    else:
        target_labels = {f"{row['id']} - {row['target']}": row for row in targets}
        selected_label = st.selectbox("Select target", options=list(target_labels.keys()))
        intensity = st.selectbox("Scan intensity", options=["low", "medium", "high"], index=0)
        auth_check = st.checkbox("I confirm permission to scan this target now")
        if st.button("Run Safe Scan"):
            if not auth_check:
                st.warning("You must confirm authorization before scanning.")
            else:
                with st.spinner("Running safe, non-destructive checks..."):
                    scan_id, summary, findings = run_scan(target_labels[selected_label], intensity)
                st.success(f"Scan completed. Scan ID: {scan_id}")
                st.subheader("Summary")
                st.json(summary)
                if findings:
                    st.subheader("Findings")
                    st.dataframe(pd.DataFrame(findings), use_container_width=True)
                    distribution = severity_distribution(findings)
                    st.subheader("Severity Distribution")
                    st.bar_chart(pd.DataFrame.from_dict(distribution, orient="index", columns=["count"]))

                    if st.button("Generate HTML Report"):
                        path = generate_html_report(
                            target=target_labels[selected_label]["target"], scan_summary=summary, findings=findings
                        )
                        add_report(scan_id=scan_id, path=path)
                        st.success(f"Report generated: {path}")
                else:
                    st.info("No findings detected by automated checks.")

    st.header("Scan History")
    scans = list_scans()
    if scans:
        history_df = pd.DataFrame(
            [
                {
                    "scan_id": s["id"],
                    "target": s["target"],
                    "status": s["status"],
                    "intensity": s["scan_intensity"],
                    "created_at": s["created_at"],
                }
                for s in scans
            ]
        )
        st.dataframe(history_df, use_container_width=True)
        selected_scan = st.selectbox("View findings for scan", options=[s["id"] for s in scans])
        findings = list_findings_for_scan(selected_scan)
        if findings:
            st.dataframe(pd.DataFrame(findings), use_container_width=True)
    else:
        st.info("No scans recorded yet.")


if __name__ == "__main__":
    dashboard()
