from http.cookies import SimpleCookie
from .common import finding

def check(url, headers, is_https=True):
    raw = headers.get_list("set-cookie") if hasattr(headers,"get_list") else []
    out=[]
    for entry in raw:
        c=SimpleCookie();
        try: c.load(entry)
        except Exception: continue
        for name,m in c.items():
            low=entry.lower()
            if is_https and "secure" not in low: out.append(finding("Cookie Missing Secure Flag","MEDIUM","Confirmed","Cookies",url,"A cookie is set without Secure on an HTTPS page.",f"Cookie {name} lacks Secure; value redacted.","The cookie could be exposed if transmitted over an insecure channel.","Set the Secure attribute for cookies intended for HTTPS."))
            if "httponly" not in low: out.append(finding("Cookie Missing HttpOnly Flag","MEDIUM","Confirmed","Cookies",url,"A cookie is set without HttpOnly.",f"Cookie {name} lacks HttpOnly; value redacted.","Client-side script may be able to access the cookie.","Set HttpOnly for cookies not needed by JavaScript."))
            if "samesite" not in low: out.append(finding("Cookie Missing SameSite Attribute","LOW","Confirmed","Cookies",url,"A cookie lacks an explicit SameSite policy.",f"Cookie {name} lacks SameSite; value redacted.","Cross-site request behavior may be less restricted than intended.","Set SameSite=Lax or Strict where compatible."))
    return out
