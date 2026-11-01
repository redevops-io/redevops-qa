"""Reviewed Robot Framework library for the order-discount suite: one keyword, one read-only request to the fixture app's JSON API.

It reads the base URL from ``QA_BASE_URL`` (the only variable the Robot adapter passes), accepts a loopback ``http`` URL only, does not use a proxy, does not
follow a redirect, and returns the ``total_cents`` the app reports. It judges nothing. Its sha256 is frozen in the plan lock, and the Robot adapter refuses to run
a library file that is not on the reviewed list with that hash."""
import json
import os
import urllib.error
import urllib.parse
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _base():
    base = os.environ.get("QA_BASE_URL", "")
    parts = urllib.parse.urlsplit(base)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or parts.port is None or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise AssertionError("QA_BASE_URL must be an http loopback origin (http://127.0.0.1:PORT)")
    return f"http://127.0.0.1:{parts.port}"


def get_order_total_cents(order_id):
    """Total of the order in integer cents, as the app reports it."""
    order_id = str(order_id)
    if not order_id.isdigit() or len(order_id) > 9:
        raise AssertionError("an order id is 1 to 9 digits")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(f"{_base()}/api/orders/{order_id}", timeout=5) as resp:
            body = json.loads(resp.read(65536).decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise AssertionError(f"the order API did not answer ({type(exc).__name__})")
    total = body.get("total_cents")
    if type(total) is not int:
        raise AssertionError("the order API answered without an integer total_cents")
    return total
