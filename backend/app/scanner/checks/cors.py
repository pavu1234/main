from .common import finding

def check(url, headers):
    o=headers.get("access-control-allow-origin"); c=headers.get("access-control-allow-credentials","").lower()
    if o == "*" and c == "true":
        return [finding("Potential Overly Permissive CORS Policy","MEDIUM","High","CORS",url,"Wildcard ACAO was observed together with credentials enabled.","Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true","This combination is suspicious, though browser enforcement and endpoint behavior must be reviewed.","Restrict allowed origins and review credential requirements.",owasp="A05 Security Misconfiguration")]
    if o == "*":
        return [finding("Permissive CORS Origin Policy","INFO","Confirmed","CORS",url,"The response allows any origin. This is not automatically exploitable.","Access-Control-Allow-Origin: *; credentials not observed as enabled.","Public cross-origin reads may be intentional for non-sensitive resources.","Confirm wildcard CORS is intended for this resource.")]
    return []
