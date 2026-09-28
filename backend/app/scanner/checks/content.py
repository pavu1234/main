import re
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse
from bs4 import BeautifulSoup
from .common import finding

ERROR_PATTERNS=[r"Traceback \(most recent call last\)",r"SQLSTATE\[",r"You have an error in your SQL syntax",r"psycopg2\.",r"sqlite3\.OperationalError",r"ORA-\d{5}",r"System\.Data\.SqlClient",r"/var/www/",r"C:\\\\inetpub\\"]

def analyze_html(url, text, headers):
    soup=BeautifulSoup(text,"lxml"); out=[]; is_https=url.startswith("https://")
    server=headers.get("server",""); powered=headers.get("x-powered-by","")
    if powered or re.search(r"\d+\.\d+",server): out.append(finding("Technology Version Disclosure","LOW","High","Information Disclosure",url,"Response headers reveal implementation details or a version string.",f"Server: {server or '[not set]'}; X-Powered-By: {powered or '[not set]'}","Version disclosure can help attackers tailor probes against known weaknesses.","Minimize unnecessary version and framework headers.",owasp="A05 Security Misconfiguration"))
    for pat in ERROR_PATTERNS:
        if re.search(pat,text,re.I): out.append(finding("Verbose Error or Internal Detail Exposure","MEDIUM","High","Information Disclosure",url,"The response appears to expose an error trace, database error, or internal path.",f"Matched safe diagnostic pattern: {pat}","Internal implementation details can aid targeted attacks.","Return generic production errors and log details server-side.",owasp="A05 Security Misconfiguration")); break
    if is_https:
        for tag,attr,active in [("script","src",True),("link","href",True),("iframe","src",True),("form","action",True),("img","src",False)]:
            for el in soup.find_all(tag):
                v=el.get(attr)
                if v and v.startswith("http://"):
                    out.append(finding("Active Mixed Content" if active else "Passive Mixed Content","MEDIUM" if active else "LOW","Confirmed","Mixed Content",url,"An HTTPS page references a resource over HTTP.",f"{tag}[{attr}] -> {v}","Insecure subresources weaken transport protection.","Serve all page resources over HTTPS.",owasp="A02 Cryptographic Failures"))
    for form in soup.find_all("form"):
        method=(form.get("method") or "GET").upper(); action=urljoin(url,form.get("action") or url)
        pwd=bool(form.find("input",{"type":"password"})); names=[i.get("name","") for i in form.find_all("input")]
        if pwd and not is_https: out.append(finding("Password Form Submitted Without HTTPS","HIGH","Confirmed","Forms",url,"A password field is present on a non-HTTPS page.",f"Form action: {action}","Credentials could be exposed in transit.","Require HTTPS for all authentication pages and actions.",owasp="A02 Cryptographic Failures",cwe="CWE-319"))
        if pwd and method=="GET": out.append(finding("Sensitive Form Uses GET","MEDIUM","Confirmed","Forms",url,"A password form uses GET.",f"Form action: {action}","Sensitive values may appear in URLs, history, logs, and referrers.","Use POST for sensitive form submissions."))
        if urlparse(action).hostname and urlparse(action).hostname != urlparse(url).hostname: out.append(finding("Cross-Origin Form Action","MEDIUM","High","Forms",url,"A form submits to another origin.",f"Action: {action}","Unexpected cross-origin form submission may expose submitted data.","Verify the destination is trusted and intended."))
        if method=="POST" and not any("csrf" in n.lower() or "token" in n.lower() for n in names): out.append(finding("Potential CSRF Protection Concern","LOW","Low","Forms",url,"No obvious CSRF token field was found. Other protections may still exist.","No input name containing csrf/token was observed.","State-changing requests may require anti-CSRF protections.","Manually verify SameSite, custom headers, origin validation, or framework CSRF controls."))
    for script in soup.find_all("script",src=True):
        src=urljoin(url,script["src"])
        if src.endswith(".js"): pass
    return out,soup
