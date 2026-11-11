
import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).parent / "sentinel.db"

VALID_ALERT_STATUSES = (
    "new",
    "investigating",
    "resolved"
)


def get_connection():
    """
    Open a SQLite database connection.

    Foreign keys are enabled so alert-event
    relationships remain consistent.
    """
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    """
    Create the database tables if necessary.

    Safely migrate existing databases by adding
    the alert status column when it is missing.
    """

    with get_connection() as connection:

        # ====================================
        # LOGIN EVENTS TABLE
        # ====================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)

        # ====================================
        # SECURITY ALERTS TABLE
        # ====================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
                    CHECK (
                        status IN (
                            'new',
                            'investigating',
                            'resolved'
                        )
                    )
            )
        """)

        # ====================================
        # MIGRATE EXISTING ALERTS TABLE
        # ====================================

        columns = connection.execute(
            "PRAGMA table_info(alerts)"
        ).fetchall()

        existing_column_names = {
            column["name"]
            for column in columns
        }

        if "status" not in existing_column_names:
            connection.execute("""
                ALTER TABLE alerts
                ADD COLUMN status TEXT NOT NULL
                DEFAULT 'new'
                CHECK (
                    status IN (
                        'new',
                        'investigating',
                        'resolved'
                    )
                )
            """)

                # ====================================
        # MIGRATE INVESTIGATION NOTES
        # ====================================

        if "notes" not in existing_column_names:
            connection.execute("""
                ALTER TABLE alerts
                ADD COLUMN notes TEXT NOT NULL DEFAULT ''
            """)

        # ====================================
        # ALERT-EVENT RELATIONSHIP TABLE
        # ====================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,

                PRIMARY KEY (alert_id, event_id),

                FOREIGN KEY (alert_id)
                    REFERENCES alerts(id)
                    ON DELETE CASCADE,

                FOREIGN KEY (event_id)
                    REFERENCES events(id)
                    ON DELETE CASCADE
            )
        """)

        # ====================================
        # DATABASE INDEXES
        # ====================================

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_events_ip_timestamp
            ON events(ip_address, timestamp)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alert_events_event_id
            ON alert_events(event_id)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alerts_status
            ON alerts(status)
        """)


def save_analysis(events, alerts):
    """
    Save login events, security alerts, and
    their exact relationships.

    New alerts automatically receive
    the status 'new'.

    All changes happen in one transaction.
    """

    with get_connection() as connection:
        event_ids = []

        # ====================================
        # SAVE LOGIN EVENTS
        # ====================================

        for event in events:
            cursor = connection.execute(
                """
                INSERT INTO events
                (
                    timestamp,
                    ip_address,
                    username,
                    status
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    event["timestamp"],
                    event["ip_address"],
                    event["username"],
                    event["status"]
                )
            )

            event_ids.append(cursor.lastrowid)

        # ====================================
        # SAVE SECURITY ALERTS
        # ====================================

        for alert in alerts:
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
                    alert["type"],
                    alert["severity"],
                    alert["ip_address"],
                    alert["failed_attempts"],
                    alert["timestamp"],
                    alert["description"]
                )
            )

            alert_id = cursor.lastrowid

            # ====================================
            # SAVE ALERT-EVENT RELATIONSHIPS
            # ====================================

            event_indices = alert.get(
                "event_indices",
                []
            )

            for index in set(event_indices):

                if (
                    not isinstance(index, int)
                    or isinstance(index, bool)
                    or index < 0
                    or index >= len(event_ids)
                ):
                    raise ValueError(
                        f"Invalid event index: {index}"
                    )

                connection.execute(
                    """
                    INSERT INTO alert_events
                    (
                        alert_id,
                        event_id
                    )
                    VALUES (?, ?)
                    """,
                    (
                        alert_id,
                        event_ids[index]
                    )
                )


def get_saved_alerts(status=None):
    """
    Retrieve security alerts.

    When status is None:
        Return every alert.

    When a status is supplied:
        Return only alerts with that status.
    """

    if (
        status is not None
        and status not in VALID_ALERT_STATUSES
    ):
        raise ValueError(
            f"Invalid alert status: {status}"
        )

    with get_connection() as connection:

        if status is None:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                """
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT *
                FROM alerts
                WHERE status = ?
                ORDER BY id DESC
                """,
                (status,)
            ).fetchall()

    return [dict(row) for row in rows]


def get_saved_events():
    """
    Retrieve all saved login events.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM events
            ORDER BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


def get_alert_by_id(alert_id):
    """
    Retrieve one security alert by its ID.
    """

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

    return dict(row) if row else None


def update_alert_status(alert_id, new_status):
    """
    Update an alert's investigation status.

    Valid statuses:
        new
        investigating
        resolved

    Returns the updated alert.

    Returns None if the alert does not exist.
    """

    if new_status not in VALID_ALERT_STATUSES:
        raise ValueError(
            f"Invalid alert status: {new_status}"
        )

    with get_connection() as connection:

        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE id = ?
            """,
            (
                new_status,
                alert_id
            )
        )

        if cursor.rowcount == 0:
            return None

        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        return dict(row) if row else None


def get_alert_status_counts():
    """
    Return the number of alerts in each status.
    """

    counts = {
        "new": 0,
        "investigating": 0,
        "resolved": 0
    }

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT status, COUNT(*) AS total
            FROM alerts
            GROUP BY status
            """
        ).fetchall()

    for row in rows:
        counts[row["status"]] = row["total"]

    return counts


def get_events_for_alert(alert_id):
    """
    Return only login events explicitly
    linked to the requested security alert.
    """

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT events.*
            FROM events
            INNER JOIN alert_events
                ON events.id = alert_events.event_id
            WHERE alert_events.alert_id = ?
            ORDER BY
                events.timestamp ASC,
                events.id ASC
            """,
            (alert_id,)
        ).fetchall()

    return [dict(row) for row in rows]


def alert_has_event_links(alert_id):
    """
    Check whether an alert has explicitly
    saved event relationships.
    """

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM alert_events
            WHERE alert_id = ?
            LIMIT 1
            """,
            (alert_id,)
        ).fetchone()

    return row is not None


# ============================================
# INVESTIGATION NOTES
# ============================================

def update_alert_notes(alert_id, notes):
    """
    Save or update investigation notes for an alert.

    Notes are stored in SQLite and remain
    available after restarting Sentinel.

    Returns the updated alert.

    Returns None if the alert does not exist.
    """

    if not isinstance(notes, str):
        raise ValueError(
            "Investigation notes must be text"
        )

    if len(notes) > 10000:
        raise ValueError(
            "Investigation notes cannot exceed 10000 characters"
        )

    with get_connection() as connection:

        cursor = connection.execute(
            """
            UPDATE alerts
            SET notes = ?
            WHERE id = ?
            """,
            (
                notes,
                alert_id
            )
        )

        if cursor.rowcount == 0:
            return None

        row = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,)
        ).fetchone()

        return dict(row) if row else None

