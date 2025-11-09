# ip_tracking/views.py

from django.http import HttpResponse
from django.views.decorators.http import require_POST
from django_ratelimit.decorators import ratelimit


def login_rate(group, request):
    """
    Dynamic rate:
    - Authenticated users: 10 requests per minute
    - Anonymous users: 5 requests per minute
    """
    if request.user.is_authenticated:
        return "10/m"
    return "5/m"


@require_POST
@ratelimit(key="user_or_ip", rate=login_rate, method="POST", block=True)
def login_view(request):
    """
    Example sensitive view (login) protected by rate limiting.

    - Uses 'user_or_ip' key: authenticated users are limited per-user,
      anonymous users per IP address. :contentReference[oaicite:3]{index=3}
    - Rate is decided by `login_rate`:
        * 10/min for authenticated users
        * 5/min for anonymous users :contentReference[oaicite:4]{index=4}
    - `block=True` means that when the limit is exceeded, a
      `Ratelimited` exception is raised and a 403 is returned by default.
      :contentReference[oaicite:5]{index=5}
    """

    # Here you would normally put your real login logic
    return HttpResponse("Login OK")  # placeholder


# Optional: custom handler if you configured RATELIMIT_VIEW
def ratelimited_handler(request, exception):
    return HttpResponse("Too many requests, please try again later.", status=429)
