from urllib.parse import urlparse

def finding(title, severity, confidence, category, url, description, evidence, impact, recommendation, *, parameter=None, owasp=None, cwe=None, method="GET", detection="Automated safe response analysis"):
    return {"title": title, "severity": severity, "confidence": confidence, "category": category, "url": url, "parameter": parameter, "method": method, "description": description, "evidence": evidence, "impact": impact, "detection": detection, "recommendation": recommendation, "owasp": owasp, "cwe": cwe}
