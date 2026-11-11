
from datetime import datetime, timedelta, timezone

from detector import (
    detect_brute_force,
    detect_password_spraying,
    analyze_threats
)


BASE_TIME = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def make_event(
    minute=0,
    username="admin",
    ip_address="192.0.2.45",
    status="failed"
):
    timestamp = BASE_TIME + timedelta(minutes=minute)

    return {
        "timestamp": timestamp.isoformat(),
        "ip_address": ip_address,
        "username": username,
        "status": status
    }


def test_brute_force_detected():
    events = [
        make_event(minute=i)
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Brute Force Attempt"
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["failed_attempts"] == 5


def test_brute_force_below_threshold():
    events = [
        make_event(minute=i)
        for i in range(4)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_brute_force_outside_time_window():
    events = [
        make_event(minute=i * 10)
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_successful_logins_do_not_trigger_alerts():
    events = [
        make_event(minute=i, status="success")
        for i in range(10)
    ]

    alerts = analyze_threats(events)

    assert len(alerts) == 0


def test_password_spraying_detected():
    usernames = [
        "alice",
        "bob",
        "charlie",
        "david",
        "emma"
    ]

    events = [
        make_event(minute=i, username=username)
        for i, username in enumerate(usernames)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "Password Spraying"
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["failed_attempts"] == 5


def test_password_spraying_below_threshold():
    usernames = [
        "alice",
        "bob",
        "charlie",
        "david"
    ]

    events = [
        make_event(minute=i, username=username)
        for i, username in enumerate(usernames)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0


def test_password_spraying_outside_time_window():
    usernames = [
        "alice",
        "bob",
        "charlie",
        "david",
        "emma"
    ]

    events = [
        make_event(
            minute=i * 15,
            username=username
        )
        for i, username in enumerate(usernames)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0


def test_combined_detection():
    brute_force_events = [
        make_event(
            minute=i,
            username="admin",
            ip_address="192.0.2.45"
        )
        for i in range(5)
    ]

    spraying_events = [
        make_event(
            minute=i,
            username=username,
            ip_address="198.51.100.25"
        )
        for i, username in enumerate([
            "alice", "bob", "charlie", "david", "emma"
        ])
    ]

    alerts = analyze_threats(
        brute_force_events + spraying_events
    )

    assert len(alerts) == 2

    alert_types = {
        alert["type"]
        for alert in alerts
    }

    assert "Brute Force Attempt" in alert_types
    assert "Password Spraying" in alert_types


def test_different_ips_do_not_trigger_brute_force():
    events = [
        make_event(
            minute=i,
            ip_address=f"192.0.2.{i + 1}"
        )
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 0


def test_different_ips_do_not_trigger_password_spraying():
    events = [
        make_event(
            minute=i,
            username=f"user{i}",
            ip_address=f"192.0.2.{i + 1}"
        )
        for i in range(5)
    ]

    alerts = detect_password_spraying(events)

    assert len(alerts) == 0
