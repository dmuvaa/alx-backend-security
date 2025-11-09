from datetime import timedelta

from celery import shared_task
from django.utils import timezone
from django.db.models import Count

from .models import RequestLog, SuspiciousIP


SENSITIVE_PATHS = ["/admin", "/login"]


@shared_task
def detect_suspicious_ips():
    """
    Anomaly detection task.

    Runs hourly (configure in Celery Beat) and flags suspicious IPs:
    - IPs with > 100 requests in the last hour.
    - IPs that accessed sensitive paths (e.g., /admin, /login).
    Creates/updates SuspiciousIP entries with a reason.
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    # 1) High-volume IPs: > 100 requests in the last hour
    queryset = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in queryset:
        ip = entry["ip_address"]
        count = entry["request_count"]
        if not ip:
            continue
        reason = f"High request volume: {count} requests in the last hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # 2) IPs accessing sensitive paths in the last hour
    sensitive_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago,
        path__in=SENSITIVE_PATHS,
    ).values("ip_address", "path")

    # Use a set to avoid duplicate creations in a single run
    seen = set()
    for log in sensitive_logs:
        ip = log["ip_address"]
        path = log["path"]
        if not ip:
            continue

        key = (ip, path)
        if key in seen:
            continue
        seen.add(key)

        reason = f"Accessed sensitive path: {path}"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)