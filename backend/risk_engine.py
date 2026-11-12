
"""
Sentinel IP Risk Scoring Engine

Calculates risk scores based on suspicious
authentication activity.

Scores range from 0 to 100.
"""

from typing import Dict


def calculate_ip_risk(
    failed_logins: int,
    successful_logins: int,
    unique_usernames: int,
    alert_count: int
) -> Dict:
    """
    Calculate a risk score for an IP address.

    This is a rule-based heuristic, not a
    validated threat-intelligence reputation score.
    """

    score = 0
    reasons = []

    # Repeated failed authentication attempts
    if failed_logins >= 10:
        score += 35
        reasons.append("High number of failed login attempts")
    elif failed_logins >= 5:
        score += 20
        reasons.append("Multiple failed login attempts")
    elif failed_logins >= 3:
        score += 10
        reasons.append("Several failed login attempts")

    # Multiple targeted usernames
    if unique_usernames >= 10:
        score += 30
        reasons.append("Large number of targeted accounts")
    elif unique_usernames >= 5:
        score += 20
        reasons.append("Possible password spraying activity")

    # Previous security alerts
    if alert_count >= 3:
        score += 35
        reasons.append("IP associated with multiple security alerts")
    elif alert_count >= 1:
        score += 20
        reasons.append("IP associated with a security alert")

    # Successful logins after failures
    if failed_logins >= 3 and successful_logins >= 1:
        score += 15
        reasons.append("Successful login observed alongside failed attempts")

    # Limit score to 100
    score = min(score, 100)

    # Assign risk classification
    if score >= 80:
        risk_level = "Critical"
    elif score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not reasons:
        reasons.append("No significant suspicious activity detected")

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }
