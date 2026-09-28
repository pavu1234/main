import re
from .common import finding
PATTERNS={"Dangerous DOM sink":r"\b(innerHTML|outerHTML|document\.write|eval\s*\()","Development reference":r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?","Potential embedded secret":r"\b(?:sk_(?:live|test)_[A-Za-z0-9]{8,}|AIza[0-9A-Za-z_-]{20,})\b","Insecure HTTP endpoint":r"http://[A-Za-z0-9.-]+"}
def check(url,text):
    out=[]
    for label,pat in PATTERNS.items():
        if re.search(pat,text,re.I):
            out.append(finding(f"Potential JavaScript Risk: {label}","LOW","Medium","JavaScript",url,"Static JavaScript analysis found a pattern requiring manual review.",f"Pattern detected: {label}; sensitive values are not displayed.","The pattern can be benign or risky depending on data flow and runtime context.","Review the relevant code path manually and remove unsafe constructs or embedded secrets.",owasp="A03 Injection" if label=="Dangerous DOM sink" else None))
    return out
