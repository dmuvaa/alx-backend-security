from django.utils import timezone

from .models import RequestLog


class IPTrackingMiddleware:
    """
    Middleware that logs the IP address, timestamp, and path
    of every incoming request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

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
