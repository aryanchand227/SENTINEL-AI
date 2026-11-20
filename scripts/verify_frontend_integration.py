"""
SENTINEL AI — Phase 6: Frontend to Backend Integration Verification Script.

Executes and verifies every API endpoint used by the React SOC dashboard
against the live FastAPI backend with Synthetic Provider and Supabase / SQLite DB.
"""

from __future__ import annotations

import sys

import httpx


def test_frontend_backend_integration() -> None:
    base_url = "http://127.0.0.1:8000/api/v1"
    print(f"[*] Starting Frontend API Integration Test against: {base_url}")

    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        # 1. Health Probes
        print("\n--- 1. Testing System Health & Readiness Endpoints ---")
        live_res = client.get("/health/live")
        assert live_res.status_code == 200, f"Liveness failed: {live_res.text}"
        print(f"  [PASS] GET /health/live: {live_res.json()}")

        ready_res = client.get("/health/ready")
        assert ready_res.status_code == 200, f"Readiness failed: {ready_res.text}"
        print(f"  [PASS] GET /health/ready: status={ready_res.json().get('status')}")

        db_res = client.get("/health/db")
        assert db_res.status_code == 200, f"DB Health failed: {db_res.text}"
        db_name = db_res.json().get("database")
        db_lat = db_res.json().get("latency_ms")
        print(f"  [PASS] GET /health/db: {db_name} ({db_lat}ms)")

        # 2. Authentication
        print("\n--- 2. Testing Authentication Endpoints ---")
        login_res = client.post(
            "/auth/login",
            json={"email": "analyst@sentinel.ai", "password": "Sentinel123!"},
        )
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        token_data = login_res.json()
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"  [PASS] POST /auth/login: token received for {token_data.get('email')}")

        me_res = client.get("/auth/me", headers=headers)
        assert me_res.status_code == 200, f"Get /auth/me failed: {me_res.text}"
        user_profile = me_res.json()
        u_name = user_profile.get("display_name")
        u_role = user_profile.get("role")
        print(f"  [PASS] GET /auth/me: user={u_name} (role={u_role})")

        # 3. Provider Status & ECS Field Mappings
        print("\n--- 3. Testing Provider Status & ECS Registry ---")
        provider_res = client.get("/providers/status", headers=headers)
        assert provider_res.status_code == 200, f"Provider status failed: {provider_res.text}"
        prov_data = provider_res.json()
        p_name = prov_data.get("provider")
        p_mode = prov_data.get("data_mode")
        print(f"  [PASS] GET /providers/status: provider={p_name} (data_mode={p_mode})")
        print(f"         Approved ECS fields: {len(prov_data.get('field_mappings', {}))} mapped")

        # 4. Security Event Explorer — Query Execution
        print("\n--- 4. Testing SQS Query Execution (Event Explorer Backend) ---")
        sqs_spec = {
            "provider": "synthetic",
            "time_range": {
                "start": "2026-11-14T00:00:00Z",
                "end": "2026-11-21T00:00:00Z",
            },
            "filters": [],
            "aggregations": [
                {"type": "terms", "field": "event.category", "size": 10}
            ],
            "sort_field": "@timestamp",
            "sort_order": "desc",
            "page_size": 100,
            "intent": "Retrieve synthetic SOC telemetry for explorer",
        }
        query_res = client.post("/queries/execute", headers=headers, json={"spec": sqs_spec})
        assert query_res.status_code == 200, f"Query execution failed: {query_res.text}"
        q_data = query_res.json()
        total_hits = q_data["metadata"]["total_hits"]
        events = q_data.get("events", [])
        print(f"  [PASS] POST /queries/execute: total_hits={total_hits}, ret={len(events)}")
        assert len(events) > 0, "No events returned from synthetic provider!"
        sample_ev = events[0]
        assert "event" in sample_ev and "@timestamp" in sample_ev, "Missing canonical ECS fields!"
        s_id = sample_ev["event"]["id"]
        s_cat = sample_ev["event"]["category"]
        print(f"         Sample Event ID: {s_id} ({s_cat})")

        # Query Preview
        preview_res = client.post("/queries/preview", headers=headers, json={"spec": sqs_spec})
        assert preview_res.status_code == 200, f"Query preview failed: {preview_res.text}"
        assert preview_res.json().get("is_valid") is True
        print("  [PASS] POST /queries/preview: is_valid=True")

        # 5. Conversational Investigation Turn (AI Assistant)
        print("\n--- 5. Testing Conversational AI Investigation Workflow ---")
        conv_payload = {
            "title": "Phase 6 Frontend Verification Case",
            "provider": "synthetic",
            "data_mode": "synthetic",
        }
        conv_res = client.post("/conversations", headers=headers, json=conv_payload)
        assert conv_res.status_code == 200, f"Create conversation failed: {conv_res.text}"
        conv_id = conv_res.json()["id"]
        print(f"  [PASS] POST /conversations: id={conv_id}")

        chat_res = client.post(
            "/chat",
            headers=headers,
            json={
                "conversation_id": conv_id,
                "message": "Find accounts with failed logins in the last 24 hours.",
            },
        )
        assert chat_res.status_code == 200, f"Chat turn failed: {chat_res.text}"
        turn_data = chat_res.json()
        inv_id = turn_data["investigation_id"]
        findings = turn_data.get("findings", [])
        evidence_ids = turn_data.get("evidence_ids", [])
        print(f"  [PASS] POST /chat: investigation_id={inv_id}")
        print(f"         Validation Status: {turn_data.get('validation_status')}")
        print(f"         Result Count: {turn_data.get('result_count')} events")
        print(f"         Findings Correlated: {len(findings)}")
        print(f"         Evidence IDs: {len(evidence_ids)}")

        # Fetch conversation details
        detail_res = client.get(f"/conversations/{conv_id}", headers=headers)
        assert detail_res.status_code == 200
        msg_count = len(detail_res.json().get("messages", []))
        assert msg_count >= 2
        print(f"  [PASS] GET /conversations/{conv_id}: message stream verified ({msg_count} msgs)")

        # 6. Report Generation & Download
        print("\n--- 6. Testing Automated Report Generation & Download ---")
        for fmt in ["pdf", "json", "csv"]:
            rep_res = client.post(
                f"/investigations/{inv_id}/reports",
                headers=headers,
                json={"format": fmt, "title": f"Phase 6 Verification Report ({fmt.upper()})"},
            )
            assert rep_res.status_code == 200, f"Report failed for {fmt}: {rep_res.text}"
            rep_data = rep_res.json()
            rep_id = rep_data["id"]
            sha_short = rep_data["sha256"][:12]
            print(f"  [PASS] POST reports ({fmt}): {rep_id} ({sha_short}..)")

            # Verify download
            dl_res = client.get(f"/reports/{rep_id}/download", headers=headers)
            assert dl_res.status_code == 200, f"Download failed for {rep_id}: {dl_res.status_code}"
            assert len(dl_res.content) > 0, "Downloaded report artifact is empty!"
            print(f"  [PASS] GET /reports/{rep_id}/download: {len(dl_res.content)} bytes received")

    print("\n[SUCCESS] ALL FRONTEND API INTEGRATION ENDPOINTS VERIFIED SUCCESSFULLY!")


if __name__ == "__main__":
    try:
        test_frontend_backend_integration()
    except Exception as exc:
        print(f"\n[FAIL] Integration test failed: {exc}")
        sys.exit(1)
