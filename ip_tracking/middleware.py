from django.http import HttpResponseForbidden
from django.utils import timezone

from .models import RequestLog, BlockedIP


class IPTrackingMiddleware:
    """
    Middleware that logs the IP address, timestamp, and path
    of every incoming request and blocks blacklisted IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden: Your IP address is blocked.")

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=timezone.now(),
            path=request.path,
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "")
        return ip
