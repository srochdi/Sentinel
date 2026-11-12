
from risk_engine import calculate_ip_risk


def test_low_risk():
    result = calculate_ip_risk(
        failed_logins=0,
        successful_logins=5,
        unique_usernames=1,
        alert_count=0
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"


def test_medium_risk():
    result = calculate_ip_risk(
        failed_logins=5,
        successful_logins=0,
        unique_usernames=1,
        alert_count=1
    )

    assert result["risk_score"] == 40
    assert result["risk_level"] == "Medium"


def test_high_risk():
    result = calculate_ip_risk(
        failed_logins=10,
        successful_logins=0,
        unique_usernames=5,
        alert_count=1
    )

    assert result["risk_score"] == 75
    assert result["risk_level"] == "High"


def test_critical_risk():
    result = calculate_ip_risk(
        failed_logins=15,
        successful_logins=1,
        unique_usernames=10,
        alert_count=3
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "Critical"


def test_success_after_failures():
    result = calculate_ip_risk(
        failed_logins=3,
        successful_logins=1,
        unique_usernames=1,
        alert_count=0
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "Low"
    assert (
        "Successful login observed alongside failed attempts"
        in result["reasons"]
    )


def test_score_never_exceeds_100():
    result = calculate_ip_risk(
        failed_logins=100,
        successful_logins=20,
        unique_usernames=50,
        alert_count=10
    )

    assert result["risk_score"] == 100
