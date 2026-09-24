from fastapi.testclient import TestClient

from web_api import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_cisco_upload() -> None:
    with open("samples/cisco_noncompliant.conf", "rb") as handle:
        response = client.post(
            "/api/v1/analyses",
            files={"file": ("router.conf", handle, "text/plain")},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["vendor_detection"]["vendor"] == "cisco"
    assert body["source_file"] == "router.conf"
    assert "findings" in body
    assert "summary" in body


def test_rejects_unsupported_extension() -> None:
    response = client.post(
        "/api/v1/analyses",
        files={"file": ("router.exe", b"not config", "application/octet-stream")},
    )
    assert response.status_code == 400
