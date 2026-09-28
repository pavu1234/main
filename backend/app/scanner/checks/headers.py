from .common import finding
REQUIRED = {
 "content-security-policy": ("Missing Content-Security-Policy", "MEDIUM", "Implement a restrictive Content-Security-Policy appropriate to the application."),
 "strict-transport-security": ("Missing Strict-Transport-Security Header", "MEDIUM", "Enable HSTS after confirming HTTPS is consistently supported."),
 "x-content-type-options": ("Missing X-Content-Type-Options", "LOW", "Set X-Content-Type-Options: nosniff."),
 "referrer-policy": ("Missing Referrer-Policy", "LOW", "Set an appropriate Referrer-Policy."),
 "permissions-policy": ("Missing Permissions-Policy", "INFO", "Consider defining a Permissions-Policy for unused browser capabilities."),
}
def check(url, headers, is_https=True):
    h={k.lower():v for k,v in headers.items()}; out=[]
    for key,(title,sev,rec) in REQUIRED.items():
        if key == "strict-transport-security" and not is_https: continue
        if key not in h: out.append(finding(title,sev,"Confirmed","Security Headers",url,"A recommended response security header is absent.",f"{key} header not returned.","Missing browser-side defense-in-depth can increase exposure to related attack classes.",rec,owasp="A05 Security Misconfiguration"))
    csp=h.get("content-security-policy","")
    if "'unsafe-eval'" in csp or "'unsafe-inline'" in csp:
        out.append(finding("Potentially Weak Content-Security-Policy","LOW","High","Security Headers",url,"The CSP contains a permissive script/style directive.",f"CSP contains {'unsafe-eval' if "'unsafe-eval'" in csp else 'unsafe-inline'}.","Permissive CSP directives can reduce mitigation value.","Reduce permissive directives where application compatibility allows.",owasp="A05 Security Misconfiguration"))
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        out.append(finding("Potential Clickjacking Exposure","MEDIUM","High","Clickjacking",url,"No X-Frame-Options or CSP frame-ancestors directive was observed.","Both framing protections were absent.","The page may be frameable by another origin.","Use CSP frame-ancestors and/or X-Frame-Options as appropriate.",owasp="A05 Security Misconfiguration",cwe="CWE-1021"))
    return out
