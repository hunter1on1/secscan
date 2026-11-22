"""Cookie security flags: Secure, HttpOnly and SameSite.

Cookies usually carry the most valuable secret a website hands out: the
session ID that keeps a user logged in. Three attributes on ``Set-Cookie``
decide how well that secret is protected:

* ``Secure``   - only send the cookie over HTTPS (never in plain text).
* ``HttpOnly`` - JavaScript cannot read it, so an XSS bug cannot steal it.
* ``SameSite`` - limit when the browser attaches it to requests that start
  on *other* sites, which blunts Cross-Site Request Forgery (CSRF).

Like headers.py, everything here is pure: it receives the raw ``Set-Cookie``
header values and returns findings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from secscan.models import Category, Finding, Status

# Cookie names that usually hold a session or login token. Those are the ones
# that really need HttpOnly; analytics or UI-preference cookies are often read
# by JavaScript on purpose, so we don't penalise them.
_SESSION_NAME_RE = re.compile(
    r"sess|sid$|^sid|auth|token|jwt|login|logged|remember|user_?id|connect\.sid",
    re.IGNORECASE,
)


@dataclass
class Cookie:
    name: str
    attributes: dict[str, str] = field(default_factory=dict)  # lower-cased keys

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> str | None:
        value = self.attributes.get("samesite")
        return value.capitalize() if value else None

    @property
    def looks_like_session(self) -> bool:
        return bool(_SESSION_NAME_RE.search(self.name))


def parse_set_cookie(header: str) -> Cookie:
    """Parse one Set-Cookie value: "id=abc; Path=/; Secure; SameSite=Lax".

    Only the name and attributes matter for this check; the value is ignored
    (and never printed, since it may be a live session token).
    """
    first, *attrs = header.split(";")
    name = first.split("=", 1)[0].strip()
    attributes: dict[str, str] = {}
    for attr in attrs:
        key, _, value = attr.strip().partition("=")
        if key:
            attributes[key.lower()] = value.strip()
    return Cookie(name=name, attributes=attributes)


def _finding(check_id: str, title: str, status: Status, detail: str, **kw) -> Finding:
    return Finding(check_id, title, Category.COOKIES, status, detail, **kw)


def _names(cookies: Iterable[Cookie]) -> str:
    names = sorted({c.name for c in cookies})
    shown = ", ".join(names[:5])
    return shown + (f" (+{len(names) - 5} more)" if len(names) > 5 else "")


def check_cookies(set_cookie_headers: Iterable[str]) -> list[Finding]:
    """Grade every cookie the page sets. One finding per flag, not per cookie,
    so a site with 20 cookies is not punished 20 times for one mistake."""
    cookies = [parse_set_cookie(h) for h in set_cookie_headers if h.strip()]
    if not cookies:
        return [_finding("cookies", "Cookies", Status.INFO, "No cookies set on this page.")]

    findings: list[Finding] = []

    # --- Secure ---------------------------------------------------------------
    # Cookies prefixed __Secure- / __Host- are rejected by browsers unless they
    # are Secure, so a missing flag there would never reach a user anyway.
    insecure = [c for c in cookies if not c.secure]
    if insecure:
        findings.append(
            _finding(
                "cookie-secure",
                "Cookie Secure flag",
                Status.FAIL,
                f"{len(insecure)} cookie(s) without Secure: {_names(insecure)}",
                recommendation="Add the Secure attribute to every cookie on an HTTPS site.",
                deduction=10,
            )
        )
    else:
        findings.append(
            _finding(
                "cookie-secure",
                "Cookie Secure flag",
                Status.PASS,
                f"All {len(cookies)} cookie(s) are Secure.",
            )
        )

    # --- HttpOnly (only demanded for session-like cookies) --------------------
    exposed = [c for c in cookies if c.looks_like_session and not c.httponly]
    other = [c for c in cookies if not c.looks_like_session and not c.httponly]
    if exposed:
        findings.append(
            _finding(
                "cookie-httponly",
                "Cookie HttpOnly flag",
                Status.WARN,
                f"Session-like cookie(s) readable by JavaScript: {_names(exposed)}",
                recommendation="Add HttpOnly to session and authentication cookies.",
                deduction=5,
            )
        )
    elif other:
        findings.append(
            _finding(
                "cookie-httponly",
                "Cookie HttpOnly flag",
                Status.INFO,
                f"{len(other)} cookie(s) readable by JavaScript ({_names(other)}); none look "
                "like session cookies.",
            )
        )
    else:
        findings.append(
            _finding(
                "cookie-httponly",
                "Cookie HttpOnly flag",
                Status.PASS,
                f"All {len(cookies)} cookie(s) are HttpOnly.",
            )
        )

    # --- SameSite -------------------------------------------------------------
    missing = [c for c in cookies if c.samesite is None]
    # SameSite=None means "send on every cross-site request"; browsers reject
    # it unless the cookie is also Secure.
    none_insecure = [c for c in cookies if c.samesite == "None" and not c.secure]
    if none_insecure:
        findings.append(
            _finding(
                "cookie-samesite",
                "Cookie SameSite attribute",
                Status.FAIL,
                f"SameSite=None without Secure (browsers drop these): {_names(none_insecure)}",
                recommendation="Use SameSite=Lax, or SameSite=None together with Secure.",
                deduction=5,
            )
        )
    elif missing:
        findings.append(
            _finding(
                "cookie-samesite",
                "Cookie SameSite attribute",
                Status.WARN,
                f"{len(missing)} cookie(s) rely on the browser default: {_names(missing)}",
                recommendation="Set SameSite=Lax (or Strict) explicitly.",
                deduction=2,
            )
        )
    else:
        values = sorted({c.samesite or "" for c in cookies})
        findings.append(
            _finding(
                "cookie-samesite",
                "Cookie SameSite attribute",
                Status.PASS,
                f"Set on all cookies ({', '.join(values)}).",
            )
        )
    return findings
