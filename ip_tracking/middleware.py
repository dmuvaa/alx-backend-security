
from django.http import HttpResponseForbidden
from django.utils import timezone
from django.core.cache import cache

from .models import RequestLog, BlockedIP


class IPTrackingMiddleware:
    """
    Middleware that:
    - blocks blacklisted IPs
    - logs IP, timestamp, path
    - logs geolocation (country, city) with 24h caching
    """

    GEO_CACHE_PREFIX = "ip_geo_"
    GEO_CACHE_TTL = 60 * 60 * 24  # 24 hours (in seconds)

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # 1. Block blacklisted IPs
        if ip_address and BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Forbidden: Your IP address is blocked.")

        # 2. Resolve geolocation (country, city) with caching
        country = ""
        city = ""
        if ip_address:
            geo = self.get_geolocation_for_ip(request, ip_address) or {}
            country = geo.get("country", "") or ""
            city = geo.get("city", "") or ""

        # 3. Log the request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=timezone.now(),
            path=request.path,
            country=country,
            city=city,
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """
        Get client IP address, preferring X-Forwarded-For when behind proxies.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR", "")
        return ip

    def get_geolocation_for_ip(self, request, ip_address):
        """
        Get geolocation (country, city) for an IP.

        - First, try the Django cache (24h TTL).
        - If missing, pull from `request.geolocation` populated by
          `django_ip_geolocation.middleware.IpGeolocationMiddleware`,
          then store in cache.
        """
        cache_key = f"{self.GEO_CACHE_PREFIX}{ip_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        country = ""
        city = ""

        # django-ip-geolocation attaches data to request.geolocation
        location = getattr(request, "geolocation", None)

        if location:
            # Try dict-style first
            if isinstance(location, dict):
                # country is usually a dict with 'name' and 'code'
                country_info = location.get("country") or {}
                if isinstance(country_info, dict):
                    country = (
                        country_info.get("name")
                        or country_info.get("code")
                        or ""
                    )
                city = location.get("city") or ""
            else:
                # Fallback for object-style attribute access
                country_info = getattr(location, "country", None)
                if isinstance(country_info, dict):
                    country = (
                        country_info.get("name")
                        or country_info.get("code")
                        or ""
                    )
                city = getattr(location, "city", "") or ""

        data = {"country": country, "city": city}
        cache.set(cache_key, data, self.GEO_CACHE_TTL)
        return data
