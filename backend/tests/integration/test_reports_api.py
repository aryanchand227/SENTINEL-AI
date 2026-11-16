"""
Integration tests for Report generation, download, and CSV formula defense.
"""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.persistence.database import init_db


@pytest.fixture(autouse=True)
async def setup_test_db() -> None:
    await init_db()


@pytest.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestReportsAPI:
    @pytest.mark.asyncio
    async def test_generate_and_download_pdf_report(self, client: AsyncClient) -> None:
        # 1. Create a conversation and run a chat turn to generate an investigation
        conv_res = await client.post(
            "/api/v1/conversations",
            json={"title": "Report Test Investigation", "provider": "synthetic"},
        )
        assert conv_res.status_code == 200
        conv_id = conv_res.json()["id"]

        chat_res = await client.post(
            "/api/v1/chat",
            json={
                "conversation_id": conv_id,
                "message": "Find accounts with failed logins in the last 24 hours.",
            },
        )
        assert chat_res.status_code == 200
        inv_id = chat_res.json()["investigation_id"]

        # 2. Request PDF report generation
        rep_res = await client.post(
            f"/api/v1/investigations/{inv_id}/reports",
            json={"format": "pdf", "title": "SOC Incident Executive Summary"},
        )
        assert rep_res.status_code == 200
        rep_data = rep_res.json()
        assert rep_data["format"] == "pdf"
        assert rep_data["status"] == "completed"
        assert rep_data["data_mode"] == "synthetic"
        assert len(rep_data["sha256"]) == 64
        report_id = rep_data["id"]

        # 3. Verify file on disk
        artifact = Path(rep_data["artifact_path"])
        assert artifact.exists()
        pdf_bytes = artifact.read_bytes()
        assert pdf_bytes.startswith(b"%PDF")

        # 4. Verify report metadata retrieval
        meta_res = await client.get(f"/api/v1/reports/{report_id}")
        assert meta_res.status_code == 200
        assert meta_res.json()["id"] == report_id

        # 5. Download report
        dl_res = await client.get(f"/api/v1/reports/{report_id}/download")
        assert dl_res.status_code == 200
        assert dl_res.headers["content-type"] == "application/pdf"
        assert dl_res.content.startswith(b"%PDF")

    @pytest.mark.asyncio
    async def test_generate_json_report(self, client: AsyncClient) -> None:
        conv_res = await client.post(
            "/api/v1/conversations",
            json={"title": "JSON Report Test", "provider": "synthetic"},
        )
        conv_id = conv_res.json()["id"]
        chat_res = await client.post(
            "/api/v1/chat",
            json={"conversation_id": conv_id, "message": "Show suspicious PowerShell activity."},
        )
        inv_id = chat_res.json()["investigation_id"]

        # Request JSON report
        rep_res = await client.post(
            f"/api/v1/investigations/{inv_id}/reports",
            json={"format": "json", "title": "PowerShell Investigation Report"},
        )
        assert rep_res.status_code == 200
        rep_data = rep_res.json()
        assert rep_data["format"] == "json"

        # Download and verify JSON payload
        dl_res = await client.get(f"/api/v1/reports/{rep_data['id']}/download")
        assert dl_res.status_code == 200
        report_json = dl_res.json()
        assert report_json["data_mode"] == "SYNTHETIC"
        assert report_json["is_synthetic"] is True
        assert "key_findings" in report_json
        assert "evidence_table" in report_json

    @pytest.mark.asyncio
    async def test_csv_formula_injection_defense(self) -> None:
        """Verify that formula injection characters are escaped with a leading apostrophe."""
        from backend.app.reporting.service import escape_csv_field

        assert escape_csv_field("=1+1") == "'=1+1"
        assert escape_csv_field("+2+2") == "'+2+2"
        assert escape_csv_field("-SUM(A1:A10)") == "'-SUM(A1:A10)"
        assert escape_csv_field("@SUM(B1:B10)") == "'@SUM(B1:B10)"
        assert escape_csv_field("benign_user") == "benign_user"
        assert escape_csv_field(None) == ""
