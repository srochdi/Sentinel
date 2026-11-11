
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def parse_timestamp(value):
    if isinstance(value, datetime):
        timestamp = value
    else:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc)


def detect_brute_force(
    events,
    threshold=5,
    window_minutes=5
):
    """
    Detect repeated failed logins against the same
    username from the same IP address.

    Track the exact input event positions that
    contributed to the detection.
    """
    failures = defaultdict(list)
    alerts = []

    for index, event in enumerate(events):
        if event["status"] != "failed":
            continue

        key = (
            event["ip_address"],
            event["username"]
        )

        failures[key].append(
            (parse_timestamp(event["timestamp"]), index)
        )

    for (ip_address, username), attempts in failures.items():
        attempts.sort(key=lambda item: item[0])
        left = 0

        for right, (current_time, _) in enumerate(attempts):
            while (
                current_time - attempts[left][0]
                > timedelta(minutes=window_minutes)
            ):
                left += 1

            count = right - left + 1

            if count >= threshold:
                event_indices = [
                    index
                    for _, index in attempts[left:right + 1]
                ]

                alerts.append({
                    "type": "Brute Force Attempt",
                    "severity": "High",
                    "ip_address": ip_address,
                    "failed_attempts": count,
                    "timestamp": current_time.isoformat(),
                    "description": (
                        f"{count} failed login attempts against "
                        f"'{username}' within {window_minutes} minutes."
                    ),
                    "event_indices": event_indices
                })
                break

    return alerts


def detect_password_spraying(
    events,
    threshold=5,
    window_minutes=10
):
    """
    Detect failed logins against multiple different
    accounts from the same IP address.

    Track the exact events in the detection window.
    """
    failures = defaultdict(list)
    alerts = []

    for index, event in enumerate(events):
        if event["status"] != "failed":
            continue

        failures[event["ip_address"]].append(
            (
                parse_timestamp(event["timestamp"]),
                event["username"],
                index
            )
        )

    for ip_address, attempts in failures.items():
        attempts.sort(key=lambda item: item[0])

        left = 0
        username_counts = defaultdict(int)

        for right, (current_time, username, _) in enumerate(attempts):
            username_counts[username] += 1

            while (
                current_time - attempts[left][0]
                > timedelta(minutes=window_minutes)
            ):
                old_username = attempts[left][1]
                username_counts[old_username] -= 1

                if username_counts[old_username] == 0:
                    del username_counts[old_username]

                left += 1

            unique_users = len(username_counts)

            if unique_users >= threshold:
                event_indices = [
                    index
                    for _, _, index in attempts[left:right + 1]
                ]

                alerts.append({
                    "type": "Password Spraying",
                    "severity": "High",
                    "ip_address": ip_address,
                    "failed_attempts": right - left + 1,
                    "timestamp": current_time.isoformat(),
                    "description": (
                        f"Failed login attempts against "
                        f"{unique_users} different accounts "
                        f"within {window_minutes} minutes."
                    ),
                    "event_indices": event_indices
                })
                break

    return alerts


def analyze_threats(events):
    """
    Run every detection rule and combine alerts.
    """
    alerts = []

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_password_spraying(events))

    return alerts
