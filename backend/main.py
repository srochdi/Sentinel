import csv
import io

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from detector import analyze_threats


from database import (
    initialize_database,
    save_analysis,
    get_saved_alerts,
    get_saved_events,
    get_alert_by_id,
    get_events_for_alert,
    alert_has_event_links,
    update_alert_status,
    get_alert_status_counts,
    update_alert_notes
)



# ============================================
# DATABASE INITIALIZATION
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


# ============================================
# FASTAPI APPLICATION
# ============================================

app = FastAPI(
    title="Sentinel Security API",
    description="A cybersecurity threat detection platform",
    version="1.5.0",
    lifespan=lifespan
)


# ============================================
# CORS CONFIGURATION
# ============================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)


# ============================================
# REQUEST MODELS
# ============================================

class LoginEvent(BaseModel):
    timestamp: datetime
    ip_address: str
    username: str
    status: Literal["success", "failed"]


class AnalysisRequest(BaseModel):
    events: list[LoginEvent] = Field(max_length=10000)


class AlertStatusUpdate(BaseModel):
    status: Literal[
        "new",
        "investigating",
        "resolved"
    ]


class AlertNotesUpdate(BaseModel):
    notes: str = Field(max_length=10000)


# ============================================
# TIMESTAMP HELPERS
# ============================================

def parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(
            tzinfo=timezone.utc
        )

    return timestamp.astimezone(timezone.utc)


def get_detection_window(alert_type: str) -> int:
    """
    Return the detection window for each attack type.
    """

    if alert_type == "Brute Force Attempt":
        return 5

    if alert_type == "Password Spraying":
        return 10

    return 10


# ============================================
# HISTORICAL EVENT CORRELATION
# ============================================

def find_historical_events(alert, window_minutes):
    """
    Legacy investigation method.

    Used for older alerts created before exact
    alert-event relationships were introduced.

    Results are inferred from:
        - Source IP address
        - Failed login status
        - Detection time window
    """

    alert_time = parse_timestamp(
        alert["timestamp"]
    )

    window_start = alert_time - timedelta(
        minutes=window_minutes
    )

    events = get_saved_events()
    related_events = []

    for event in events:

        if event["ip_address"] != alert["ip_address"]:
            continue

        if event["status"] != "failed":
            continue

        event_time = parse_timestamp(
            event["timestamp"]
        )

        if window_start <= event_time <= alert_time:
            related_events.append(event)

    related_events.sort(
        key=lambda event: (
            parse_timestamp(event["timestamp"]),
            event["id"]
        )
    )

    return related_events


# ============================================
# ROOT ENDPOINT
# ============================================

@app.get("/")
def home():
    return {
        "application": "Sentinel",
        "message": "Security API is running",
        "status": "online"
    }


# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }


# ============================================
# THREAT ANALYSIS
# ============================================

@app.post("/analyze")
def analyze_events(request: AnalysisRequest):
    """
    Analyze login events and save detected threats.

    New security alerts automatically receive
    the status 'new' in SQLite.
    """

    events = [
        event.model_dump(mode="json")
        for event in request.events
    ]

    alerts = analyze_threats(events)

    save_analysis(events, alerts)

    # Remove internal event correlation indices
    # from the public API response.

    public_alerts = [
        {
            key: value
            for key, value in alert.items()
            if key != "event_indices"
        }
        for alert in alerts
    ]

    return {
        "events_analyzed": len(events),
        "total_alerts": len(alerts),
        "alerts": public_alerts,
        "saved_to_database": True
    }


# ============================================
# RETRIEVE SECURITY ALERTS
# ============================================

@app.get("/alerts")
def get_alerts(
    status: Literal[
        "new",
        "investigating",
        "resolved"
    ] | None = None
):
    """
    Retrieve all security alerts.

    Optional status filtering:

        /alerts
        /alerts?status=new
        /alerts?status=investigating
        /alerts?status=resolved
    """

    alerts = get_saved_alerts(status=status)

    return {
        "total_alerts": len(alerts),
        "alerts": alerts
    }


# ============================================
# ALERT STATUS COUNTS
# ============================================

@app.get("/alerts/status/counts")
def get_status_counts():
    """
    Return the number of security alerts
    in each investigation status.
    """

    counts = get_alert_status_counts()

    return {
        "new": counts["new"],
        "investigating": counts["investigating"],
        "resolved": counts["resolved"],
        "total": sum(counts.values())
    }


# ============================================
# UPDATE ALERT STATUS
# ============================================

@app.patch("/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: int,
    request: AlertStatusUpdate
):
    """
    Change an alert's investigation status.

    Supported statuses:
        new
        investigating
        resolved

    Example request:

        PATCH /alerts/12/status

        {
            "status": "investigating"
        }
    """

    updated_alert = update_alert_status(
        alert_id,
        request.status
    )

    if updated_alert is None:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    return {
        "message": "Alert status updated successfully",
        "alert": updated_alert
    }

# ============================================
# UPDATE INVESTIGATION NOTES
# ============================================

@app.patch("/alerts/{alert_id}/notes")
def change_alert_notes(
    alert_id: int,
    request: AlertNotesUpdate
):
    """
    Save or edit investigation notes
    for an existing security alert.
    """

    updated_alert = update_alert_notes(
        alert_id,
        request.notes
    )

    if updated_alert is None:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    return {
        "message": "Investigation notes saved successfully",
        "alert": updated_alert
    }

# ============================================
# INVESTIGATE SECURITY ALERT
# ============================================

@app.get("/alerts/{alert_id}/investigate")
def investigate_alert(alert_id: int):
    """
    Investigate a security alert.

    Newer alerts:
        Retrieve exactly linked events.

    Historical alerts:
        Use IP and timestamp correlation.

    Preserve the existing response structure
    expected by the React dashboard.
    """

    alert = get_alert_by_id(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    window_minutes = get_detection_window(
        alert["type"]
    )

    has_exact_links = alert_has_event_links(
        alert_id
    )

    if has_exact_links:

        related_events = get_events_for_alert(
            alert_id
        )

        correlation_method = "exact"

    else:

        related_events = find_historical_events(
            alert,
            window_minutes
        )

        correlation_method = "historical"

    affected_accounts = sorted({
        event["username"]
        for event in related_events
    })

    return {
        "alert": alert,
        "investigation": {
            "source_ip": alert["ip_address"],
            "attack_type": alert["type"],
            "severity": alert["severity"],
            "detection_time": alert["timestamp"],
            "window_minutes": window_minutes,
            "related_event_count": len(
                related_events
            ),
            "affected_accounts": affected_accounts,
            "affected_account_count": len(
                affected_accounts
            ),
            "related_events": related_events,
            "correlation_method": correlation_method
        }
    }


# ============================================
# RETRIEVE LOGIN EVENTS
# ============================================

@app.get("/events")
def get_events():
    """
    Retrieve all saved login events.
    """

    events = get_saved_events()

    return {
        "total_events": len(events),
        "events": events
    }


# ============================================
# CSV EXPORT
# ============================================

def safe_csv_value(value):
    """
    Prevent spreadsheet applications from
    interpreting exported text as formulas.
    """
    text = str(value if value is not None else "")

    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text

    return text


@app.get("/export/alerts")
def export_alerts():
    """
    Export all security alerts to CSV.
    """

    alerts = get_saved_alerts()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Alert ID",
        "Attack Type",
        "Severity",
        "Source IP",
        "Failed Attempts",
        "Detection Time",
        "Description",
        "Status",
        "Investigation Notes"
    ])

    for alert in alerts:
        writer.writerow([
            alert["id"],
            safe_csv_value(alert["type"]),
            safe_csv_value(alert["severity"]),
            safe_csv_value(alert["ip_address"]),
            alert["failed_attempts"],
            safe_csv_value(alert["timestamp"]),
            safe_csv_value(alert["description"]),
            safe_csv_value(alert["status"]),
            safe_csv_value(alert.get("notes", ""))
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="sentinel_alerts.csv"'
        }
    )


@app.get("/export/events")
def export_events():
    """
    Export all recorded login events to CSV.
    """

    events = get_saved_events()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Event ID",
        "Timestamp",
        "Source IP",
        "Username",
        "Login Status"
    ])

    for event in events:
        writer.writerow([
            event["id"],
            safe_csv_value(event["timestamp"]),
            safe_csv_value(event["ip_address"]),
            safe_csv_value(event["username"]),
            safe_csv_value(event["status"])
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="sentinel_events.csv"'
        }
    )
