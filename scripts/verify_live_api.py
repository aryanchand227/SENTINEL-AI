"""
Verification script for running live end-to-end investigation workflow
against the running SENTINEL AI backend.
"""

from __future__ import annotations

import httpx


def main() -> None:
    client = httpx.Client(base_url="http://127.0.0.1:8000/api/v1")

    # 1. Login
    resp = client.post(
        "/auth/login",
        json={"email": "analyst@sentinel.ai", "password": "Sentinel123!"},
    )
    print("1. Login status:", resp.status_code)
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Create conversation
    conv = client.post(
        "/conversations",
        headers=headers,
        json={"title": "SSH Brute Force Live Walkthrough"},
    ).json()
    conv_id = conv["id"]
    print("2. Created conversation:", conv_id)

    # 3. Turn 1
    t1_resp = client.post(
        "/chat",
        headers=headers,
        json={
            "conversation_id": conv_id,
            "message": "Find accounts with failed logins in the last 24 hours.",
        },
    )
    turn1 = t1_resp.json()
    print("3. Turn 1 Validation:", turn1.get("validation_status"))
    print("   Turn 1 Event Hits:", turn1.get("result_count"))
    print("   Turn 1 Findings:", len(turn1.get("findings", [])))
    print("   Turn 1 Assistant Message:", turn1.get("assistant_message"))
    inv_id = turn1["investigation_id"]

    # 4. Turn 2
    t2_resp = client.post(
        "/chat",
        headers=headers,
        json={
            "conversation_id": conv_id,
            "investigation_id": inv_id,
            "message": "Did any of those accounts log in successfully afterwards?",
        },
    )
    turn2 = t2_resp.json()
    print("4. Turn 2 Validation:", turn2.get("validation_status"))
    print("   Turn 2 Event Hits:", turn2.get("result_count"))
    print("   Turn 2 Findings:", len(turn2.get("findings", [])))
    for f in turn2.get("findings", []):
        print(f"     - [{f['severity'].upper()}] {f['title']}: {f['description']}")
    print("   Turn 2 Assistant Message:", turn2.get("assistant_message"))

    # 5. Generate PDF report
    pdf_resp = client.post(
        f"/investigations/{inv_id}/reports",
        headers=headers,
        json={
            "format": "pdf",
            "title": "SSH Brute Force and Compromise Report",
        },
    )
    assert pdf_resp.status_code in (200, 201), f"Generate PDF failed: {pdf_resp.text}"
    pdf_rep = pdf_resp.json()
    pdf_id = pdf_rep["id"]
    print(f"5. Generated PDF Report: {pdf_id} (Status: {pdf_rep['status']})")

    # 6. Download PDF report
    download_pdf = client.get(f"/reports/{pdf_id}/download", headers=headers)
    pdf_bytes_len = len(download_pdf.content)
    print(f"6. Downloaded PDF Report: Status={download_pdf.status_code}, Bytes={pdf_bytes_len}")
    assert download_pdf.status_code == 200
    assert len(download_pdf.content) > 1000

    # 7. Generate CSV report
    csv_resp = client.post(
        f"/investigations/{inv_id}/reports",
        headers=headers,
        json={
            "format": "csv",
            "title": "SSH Compromise Evidence Export",
        },
    )
    assert csv_resp.status_code in (200, 201), f"Generate CSV failed: {csv_resp.text}"
    csv_rep = csv_resp.json()
    csv_id = csv_rep["id"]
    print(f"7. Generated CSV Report: {csv_id} (Status: {csv_rep['status']})")

    # 8. Download CSV report
    download_csv = client.get(f"/reports/{csv_id}/download", headers=headers)
    csv_bytes_len = len(download_csv.content)
    print(f"8. Downloaded CSV Report: Status={download_csv.status_code}, Bytes={csv_bytes_len}")
    assert download_csv.status_code == 200
    assert len(download_csv.content) > 200

    print("\n>>> ALL LIVE VERIFICATIONS COMPLETED SUCCESSFULLY! <<<")


if __name__ == "__main__":
    main()
