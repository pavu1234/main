import csv, io, json
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors

def rows(findings):
    return [{"id":f.id,"title":f.title,"severity":f.severity,"confidence":f.confidence,"category":f.category,"url":f.url,"description":f.description,"evidence":f.evidence,"impact":f.impact,"recommendation":f.recommendation,"owasp":f.owasp,"cwe":f.cwe,"status":f.status} for f in findings]
def json_report(scan, findings):
    return json.dumps({"scan":{"id":scan.id,"target":scan.target,"status":scan.status,"security_score":scan.security_score,"pages_scanned":scan.pages_scanned,"duration":scan.duration},"findings":rows(findings),"limitations":"Automated security scanning cannot identify every security vulnerability. Results may contain false positives or false negatives. Findings requiring exploitation, authenticated business-logic analysis or manual testing should be reviewed by an authorized security professional."},indent=2)
def csv_report(findings):
    o=io.StringIO(); w=csv.DictWriter(o,fieldnames=list(rows(findings)[0].keys()) if findings else ["id","title","severity"]); w.writeheader(); [w.writerow(r) for r in rows(findings)]; return o.getvalue()
def pdf_report(scan, findings):
    b=io.BytesIO(); d=SimpleDocTemplate(b,pagesize=A4); s=getSampleStyleSheet(); story=[Paragraph("WebGuard Pro Security Assessment",s["Title"]),Spacer(1,18),Paragraph(f"Target: {scan.target}",s["BodyText"]),Paragraph(f"Security Score: {scan.security_score}/100",s["Heading2"]),Paragraph(f"Pages scanned: {scan.pages_scanned} | Requests: {scan.requests_sent} | Duration: {scan.duration:.2f}s",s["BodyText"]),Spacer(1,12),Paragraph("Executive Summary",s["Heading1"]),Paragraph(f"WebGuard performed a safe automated assessment and recorded {len(findings)} findings. Confirmed and potential findings should be reviewed in context.",s["BodyText"]),PageBreak(),Paragraph("Detailed Findings",s["Heading1"])]
    for f in findings:
        story += [Paragraph(f"{f.severity} — {f.title}",s["Heading2"]),Paragraph(f"URL: {f.url}",s["BodyText"]),Paragraph(f"Confidence: {f.confidence} | Category: {f.category}",s["BodyText"]),Paragraph(f"Description: {f.description}",s["BodyText"]),Paragraph(f"Evidence: {f.evidence}",s["BodyText"]),Paragraph(f"Recommendation: {f.recommendation}",s["BodyText"]),Spacer(1,12)]
    story += [PageBreak(),Paragraph("Limitations",s["Heading1"]),Paragraph("Automated security scanning cannot identify every security vulnerability. Results may contain false positives or false negatives. Findings requiring exploitation, authenticated business-logic analysis or manual testing should be reviewed by an authorized security professional.",s["BodyText"])]
    d.build(story); return b.getvalue()
