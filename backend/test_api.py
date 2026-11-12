
import sqlite3

import pytest
from fastapi.testclient import TestClient

import database
from main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Every test gets its own temporary SQLite database.
    # Your real sentinel.db is never modified.
    test_database = tmp_path / "test_sentinel.db"
    monkeypatch.setattr(database, "DATABASE_PATH", test_database)

    with TestClient(app) as test_client:
        yield test_client


def make_events(usernames, ip_address="192.0.2.45"):
    return [
        {
            "timestamp": f"2026-11-11T12:{i:02d}:00Z",
            "ip_address": ip_address,
            "username": username,
            "status": "failed"
        }
        for i, username in enumerate(usernames)
    ]


def get_newest_alert_id(client):
    response = client.get("/alerts")
    assert response.status_code == 200

    alerts = response.json()["alerts"]
    assert alerts, "Expected at least one saved alert"

    return alerts[0]["id"]


# ========================================
# EXISTING API TESTS
# ========================================

def test_health_endpoint(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_empty_database(client):
    alerts = client.get("/alerts").json()
    events = client.get("/events").json()

    assert alerts["total_alerts"] == 0
    assert events["total_events"] == 0


def test_brute_force_api(client):
    payload = {
        "events": make_events(["admin"] * 5)
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 200

    result = response.json()

    assert result["events_analyzed"] == 5
    assert result["total_alerts"] == 1
    assert result["alerts"][0]["type"] == "Brute Force Attempt"
    assert result["saved_to_database"] is True

    saved_events = client.get("/events").json()
    saved_alerts = client.get("/alerts").json()

    assert saved_events["total_events"] == 5
    assert saved_alerts["total_alerts"] == 1


def test_password_spraying_api(client):
    payload = {
        "events": make_events(
            ["alice", "bob", "charlie", "david", "emma"]
        )
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 200

    result = response.json()

    assert result["total_alerts"] == 1
    assert result["alerts"][0]["type"] == "Password Spraying"


def test_invalid_login_status(client):
    payload = {
        "events": [
            {
                "timestamp": "2026-11-11T12:00:00Z",
                "ip_address": "192.0.2.45",
                "username": "admin",
                "status": "unknown"
            }
        ]
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 422

    saved_events = client.get("/events").json()
    assert saved_events["total_events"] == 0


def test_database_survives_new_connection(client):
    payload = {
        "events": make_events(["admin"] * 5)
    }

    client.post("/analyze", json=payload)

    with sqlite3.connect(database.DATABASE_PATH) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

    assert count == 5


# ========================================
# NEW INVESTIGATION TESTS
# ========================================

def test_brute_force_exact_investigation(client):
    """
    Verify that a brute-force alert has five
    explicitly linked failed login events.
    """
    response = client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    assert response.status_code == 200

    alert_id = get_newest_alert_id(client)

    investigation_response = client.get(
        f"/alerts/{alert_id}/investigate"
    )

    assert investigation_response.status_code == 200

    investigation = investigation_response.json()["investigation"]

    assert investigation["correlation_method"] == "exact"
    assert investigation["attack_type"] == "Brute Force Attempt"
    assert investigation["related_event_count"] == 5
    assert investigation["affected_accounts"] == ["admin"]
    assert investigation["affected_account_count"] == 1
    assert investigation["window_minutes"] == 5

    assert all(
        event["status"] == "failed"
        for event in investigation["related_events"]
    )


def test_password_spraying_exact_investigation(client):
    """
    Verify that password spraying correctly
    identifies five distinct affected accounts.
    """
    usernames = [
        "alice",
        "bob",
        "charlie",
        "david",
        "emma"
    ]

    response = client.post(
        "/analyze",
        json={"events": make_events(usernames)}
    )

    assert response.status_code == 200

    alert_id = get_newest_alert_id(client)

    result = client.get(
        f"/alerts/{alert_id}/investigate"
    ).json()

    investigation = result["investigation"]

    assert investigation["correlation_method"] == "exact"
    assert investigation["attack_type"] == "Password Spraying"
    assert investigation["related_event_count"] == 5
    assert investigation["affected_account_count"] == 5
    assert investigation["affected_accounts"] == sorted(usernames)
    assert investigation["window_minutes"] == 10


def test_investigation_excludes_unrelated_events(client):
    """
    Verify that events not contributing to an
    alert are excluded, even when the IP matches.
    """
    events = make_events(["admin"] * 5)

    events.append({
        "timestamp": "2026-11-11T12:04:30Z",
        "ip_address": "192.0.2.45",
        "username": "unrelated",
        "status": "success"
    })

    events.append({
        "timestamp": "2026-11-11T12:04:40Z",
        "ip_address": "198.51.100.99",
        "username": "outsider",
        "status": "failed"
    })

    response = client.post(
        "/analyze",
        json={"events": events}
    )

    assert response.status_code == 200
    assert response.json()["total_alerts"] == 1

    alert_id = get_newest_alert_id(client)

    investigation = client.get(
        f"/alerts/{alert_id}/investigate"
    ).json()["investigation"]

    assert investigation["correlation_method"] == "exact"
    assert investigation["related_event_count"] == 5
    assert investigation["affected_accounts"] == ["admin"]

    usernames = [
        event["username"]
        for event in investigation["related_events"]
    ]

    assert "unrelated" not in usernames
    assert "outsider" not in usernames


def test_investigation_event_relationships_in_database(client):
    """
    Verify that SQLite stores five relationships
    between the alert and its triggering events.
    """
    response = client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    assert response.status_code == 200

    alert_id = get_newest_alert_id(client)

    with sqlite3.connect(database.DATABASE_PATH) as connection:
        rows = connection.execute(
            """
            SELECT alert_id, event_id
            FROM alert_events
            WHERE alert_id = ?
            """,
            (alert_id,)
        ).fetchall()

    assert len(rows) == 5
    assert all(row[0] == alert_id for row in rows)
    assert len({row[1] for row in rows}) == 5


def test_investigation_missing_alert(client):
    """
    Requesting an alert that does not exist
    must return HTTP 404.
    """
    response = client.get(
        "/alerts/999999/investigate"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Security alert not found"


def test_historical_alert_fallback(client):
    """
    Older alerts without explicit event links
    should still support historical investigation.
    """
    events = make_events(["legacy_admin"] * 5)

    with sqlite3.connect(database.DATABASE_PATH) as connection:
        for event in events:
            connection.execute(
                """
                INSERT INTO events
                (timestamp, ip_address, username, status)
                VALUES (?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["ip_address"],
                    event["username"],
                    event["status"]
                )
            )

        cursor = connection.execute(
            """
            INSERT INTO alerts
            (
                type,
                severity,
                ip_address,
                failed_attempts,
                timestamp,
                description
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "Brute Force Attempt",
                "High",
                "192.0.2.45",
                5,
                "2026-11-11T12:04:00Z",
                "Historical brute-force alert"
            )
        )

        alert_id = cursor.lastrowid

    response = client.get(
        f"/alerts/{alert_id}/investigate"
    )

    assert response.status_code == 200

    investigation = response.json()["investigation"]

    assert investigation["correlation_method"] == "historical"
    assert investigation["related_event_count"] == 5
    assert investigation["affected_accounts"] == ["legacy_admin"]


# ========================================
# INVESTIGATION NOTES TESTS
# ========================================

def test_save_investigation_notes(client):
    response = client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )
    assert response.status_code == 200

    alert_id = get_newest_alert_id(client)

    response = client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": "Investigated suspicious activity."}
    )

    assert response.status_code == 200
    assert response.json()["alert"]["notes"] == (
        "Investigated suspicious activity."
    )


def test_update_investigation_notes(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)

    client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": "Initial investigation."}
    )

    response = client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": "Investigation completed."}
    )

    assert response.status_code == 200
    assert response.json()["alert"]["notes"] == (
        "Investigation completed."
    )


def test_investigation_notes_persist(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)
    saved_note = "Reviewed affected accounts."

    client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": saved_note}
    )

    with sqlite3.connect(database.DATABASE_PATH) as connection:
        row = connection.execute(
            "SELECT notes FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

    assert row is not None
    assert row[0] == saved_note

    response = client.get(
        f"/alerts/{alert_id}/investigate"
    )

    assert response.status_code == 200
    assert response.json()["alert"]["notes"] == saved_note


def test_investigation_notes_too_long(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)

    response = client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": "A" * 10001}
    )

    assert response.status_code == 422


def test_investigation_notes_missing_alert(client):
    response = client.patch(
        "/alerts/999999/notes",
        json={"notes": "Test note"}
    )

    assert response.status_code == 404


# ========================================
# ALERT STATUS TESTS
# ========================================

def test_update_alert_status(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "investigating"}
    )

    assert response.status_code == 200
    assert response.json()["alert"]["status"] == "investigating"

    counts = client.get("/alerts/status/counts").json()

    assert counts["investigating"] == 1
    assert counts["new"] == 0
    assert counts["total"] == 1


def test_invalid_alert_status(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "deleted"}
    )

    assert response.status_code == 422


# ========================================
# CSV EXPORT TESTS
# ========================================

def test_export_alerts_csv(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    alert_id = get_newest_alert_id(client)

    client.patch(
        f"/alerts/{alert_id}/notes",
        json={"notes": "Reviewed security incident."}
    )

    response = client.get("/export/alerts")

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "sentinel_alerts.csv" in (
        response.headers["content-disposition"]
    )

    csv_content = response.text

    assert "Alert ID" in csv_content
    assert "Attack Type" in csv_content
    assert "Investigation Notes" in csv_content
    assert "Brute Force Attempt" in csv_content
    assert "Reviewed security incident." in csv_content


def test_export_events_csv(client):
    client.post(
        "/analyze",
        json={"events": make_events(["admin"] * 5)}
    )

    response = client.get("/export/events")

    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "sentinel_events.csv" in (
        response.headers["content-disposition"]
    )

    csv_content = response.text

    assert "Event ID" in csv_content
    assert "Timestamp" in csv_content
    assert "Source IP" in csv_content
    assert "Username" in csv_content
    assert "Login Status" in csv_content
    assert "admin" in csv_content


def test_risk_assessment_high(client):
    response = client.post(
        "/risk/assess",
        params={
            "failed_logins": 10,
            "successful_logins": 0,
            "unique_usernames": 5,
            "alert_count": 1
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 75
    assert data["risk_level"] == "High"
    assert len(data["reasons"]) == 3


def test_risk_assessment_low(client):
    response = client.post(
        "/risk/assess",
        params={
            "failed_logins": 0,
            "successful_logins": 5,
            "unique_usernames": 1,
            "alert_count": 0
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 0
    assert data["risk_level"] == "Low"


def test_risk_assessment_critical(client):
    response = client.post(
        "/risk/assess",
        params={
            "failed_logins": 15,
            "successful_logins": 1,
            "unique_usernames": 10,
            "alert_count": 3
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["risk_score"] == 100
    assert data["risk_level"] == "Critical"


def test_database_ip_risk_no_activity(client):
    response = client.get("/risk/ip/192.0.2.250")

    assert response.status_code == 200

    data = response.json()

    assert data["ip_address"] == "192.0.2.250"
    assert data["failed_logins"] == 0
    assert data["successful_logins"] == 0
    assert data["unique_usernames"] == 0
    assert data["alert_count"] == 0
    assert data["risk_score"] == 0
    assert data["risk_level"] == "Low"


def test_database_ip_risk_response_structure(client):
    response = client.get("/risk/ip/192.0.2.106")

    assert response.status_code == 200

    data = response.json()

    expected_fields = [
        "ip_address",
        "failed_logins",
        "successful_logins",
        "unique_usernames",
        "alert_count",
        "risk_score",
        "risk_level",
        "reasons",
    ]

    for field in expected_fields:
        assert field in data


def test_database_ip_risk_valid_score_range(client):
    response = client.get("/risk/ip/192.0.2.106")

    assert response.status_code == 200

    data = response.json()

    assert 0 <= data["risk_score"] <= 100

    assert data["risk_level"] in [
        "Low",
        "Medium",
        "High",
        "Critical",
    ]

    assert isinstance(data["reasons"], list)
