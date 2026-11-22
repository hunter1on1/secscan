"""Mixed content: an HTTPS page that loads resources over plain HTTP.

If a secure page pulls in ``http://`` resources, those requests travel
unencrypted and can be read or *replaced* by anyone on the network:

* **Active** mixed content (scripts, stylesheets, iframes, objects) can take
  over the whole page. Browsers block it, so it also breaks the site.
* **Passive** mixed content (images, audio, video) can be swapped or tracked.
  Modern browsers try to upgrade it to HTTPS, but it still leaks.

We parse the HTML with Python's built-in :mod:`html.parser` (no extra
dependency) and look for ``http://`` URLs in the attributes that load things.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser

from secscan.headers import parse_csp
from secscan.models import Category, Finding, Status

# Only look at the first 2 MB of HTML: enough for any real page, and it keeps
# the scan fast on huge responses.
MAX_HTML_BYTES = 2_000_000


@dataclass(frozen=True)
class Resource:
    tag: str
    url: str
    active: bool


# tag -> (attributes that load a resource, is it active content?)
_LOADERS: dict[str, tuple[tuple[str, ...], bool]] = {
    "script": (("src",), True),
    "iframe": (("src",), True),
    "frame": (("src",), True),
    "object": (("data",), True),
    "embed": (("src",), True),
    "img": (("src", "srcset"), False),
    "source": (("src", "srcset"), False),
    "audio": (("src",), False),
    "video": (("src", "poster"), False),
    "track": (("src",), False),
}


class _ResourceCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[Resource] = []

    def _add(self, tag: str, url: str, active: bool) -> None:
        if url.strip().lower().startswith("http://"):
            self.resources.append(Resource(tag, url.strip(), active))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}

        # <link rel="stylesheet" href="..."> is active; other <link> types
        # (canonical, alternate...) are just metadata, not loaded resources.
        if tag == "link":
            rel = values.get("rel", "").lower().split()
            if "stylesheet" in rel or "preload" in rel or "modulepreload" in rel:
                self._add("link", values.get("href", ""), True)
            return

        if tag not in _LOADERS:
            return
        names, active = _LOADERS[tag]
        for name in names:
            value = values.get(name, "")
            if name == "srcset":
                # "a.jpg 1x, http://x/b.jpg 2x" -> each candidate URL
                for candidate in value.split(","):
                    parts = candidate.split()
                    if parts:
                        self._add(tag, parts[0], active)
            else:
                self._add(tag, value, active)


def find_mixed_content(html: str) -> list[Resource]:
    """Return every http:// resource the page would load (duplicates removed)."""
    collector = _ResourceCollector()
    collector.feed(html[:MAX_HTML_BYTES])
    collector.close()
    return list(dict.fromkeys(collector.resources))


def _finding(status: Status, detail: str, **kw) -> Finding:
    return Finding("mixed-content", "Mixed content", Category.CONTENT, status, detail, **kw)


def _examples(resources: list[Resource], limit: int = 3) -> str:
    shown = ", ".join(f"<{r.tag}> {r.url}" for r in resources[:limit])
    more = len(resources) - limit
    return shown + (f" (+{more} more)" if more > 0 else "")


def check_mixed_content(html: str, csp: str | None = None) -> Finding:
    """Grade an HTTPS page's HTML for http:// resources."""
    resources = find_mixed_content(html)
    if not resources:
        return _finding(Status.PASS, "No http:// resources found in the page HTML.")

    active = [r for r in resources if r.active]
    passive = [r for r in resources if not r.active]
    fix = "Load every resource over https:// (or add CSP upgrade-insecure-requests)."

    # The CSP directive upgrade-insecure-requests makes the browser rewrite
    # http:// to https:// before fetching, which neutralises the problem.
    if csp and "upgrade-insecure-requests" in parse_csp(csp):
        return _finding(
            Status.INFO,
            f"{len(resources)} http:// resource(s), but CSP upgrade-insecure-requests "
            "makes browsers fetch them over HTTPS.",
        )

    if active:
        return _finding(
            Status.FAIL,
            f"{len(active)} active http:// resource(s) (scripts/styles/frames): "
            + _examples(active),
            recommendation=fix,
            deduction=15,
        )
    return _finding(
        Status.WARN,
        f"{len(passive)} passive http:// resource(s) (images/media): " + _examples(passive),
        recommendation=fix,
        deduction=5,
    )
