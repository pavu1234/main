import asyncio, json, ssl, socket, time, uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
from .scope import validate_public_target, same_host
from .http_client import SafeHttpClient
from .crawler import Crawler
from .checks import headers as headers_check, cookies as cookies_check, cors as cors_check
from .checks.content import analyze_html, ERROR_PATTERNS
from .checks.javascript import check as js_check
from .checks.common import finding
from ..models.entities import Scan, Finding, Page, RequestRecord
from ..services.scoring import calculate_score
from ..services.sanitization import redact
from ..config import settings
import re

class ScannerEngine:
    def __init__(self, db: Session, scan_id: str, config: dict, event_cb=None, demo=False): self.db=db; self.scan_id=scan_id; self.config=config; self.event_cb=event_cb; self.demo=demo; self.findings=[]
    async def emit(self,stage,current=0,total=0,msg=""):
        if self.event_cb: await self.event_cb({"stage":stage,"current":current,"total":total,"message":msg})
    def add(self,f):
        self.findings.append(f)
        obj=Finding(id=f"WG-{uuid.uuid4().hex[:8].upper()}",scan_id=self.scan_id,**{k:redact(v) if isinstance(v,str) else v for k,v in f.items()}); self.db.add(obj)
    async def tls_check(self,target):
        if not target.startswith("https://"): self.add(finding("HTTP Target Without HTTPS","HIGH","Confirmed","TLS",target,"The submitted target uses HTTP.","URL scheme is http://","Traffic can be intercepted or modified in transit.","Deploy HTTPS and redirect HTTP to HTTPS.",owasp="A02 Cryptographic Failures")); return
        host=urlparse(target).hostname; port=urlparse(target).port or 443
        try:
            ctx=ssl.create_default_context(); reader,writer=await asyncio.wait_for(asyncio.open_connection(host,port,ssl=ctx,server_hostname=host),timeout=settings.request_timeout)
            sslobj=writer.get_extra_info("ssl_object"); cert=sslobj.getpeercert(); proto=sslobj.version(); writer.close(); await writer.wait_closed()
            not_after=cert.get("notAfter")
            if not_after:
                exp=datetime.strptime(not_after,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc); days=(exp-datetime.now(timezone.utc)).days
                if days<0: self.add(finding("TLS Certificate Expired","HIGH","Confirmed","TLS",target,"The TLS certificate is expired.",f"Certificate expired {abs(days)} days ago.","Clients may reject the connection and users can be exposed to interception risks.","Renew and deploy a valid certificate.",owasp="A02 Cryptographic Failures"))
                elif days<30: self.add(finding("TLS Certificate Near Expiration","LOW","Confirmed","TLS",target,"The TLS certificate expires soon.",f"Certificate expires in {days} days.","Expiry can cause service trust failures.","Renew before expiration."))
            if proto in {"TLSv1","TLSv1.1"}: self.add(finding("Legacy TLS Protocol Negotiated","MEDIUM","Confirmed","TLS",target,"A legacy TLS protocol was negotiated.",f"Protocol: {proto}","Older protocols have weaker security properties.","Disable legacy TLS versions and prefer TLS 1.2/1.3."))
        except Exception as exc: self.add(finding("TLS Validation Failed","MEDIUM","Medium","TLS",target,"TLS validation could not be completed.",f"Validation error: {type(exc).__name__}","Certificate or transport configuration may require review.","Verify certificate chain, hostname, and supported protocols."))
    async def safe_parameter_checks(self,client,page):
        if self.config.get("passive_only"): return
        p=urlparse(page["url"]); qs=parse_qsl(p.query,keep_blank_values=True)
        if not qs: return
        marker="WEBGUARD_8F92A"
        for idx,(name,val) in enumerate(qs[:4]):
            mod=qs.copy(); mod[idx]=(name,marker); u=urlunparse(p._replace(query=urlencode(mod)))
            try:
                r,b,_,_=await client.get(u); text=b.decode(r.encoding or "utf-8",errors="replace")
                if marker in text:
                    encoded="WEBGUARD_8F92A" not in text
                    self.add(finding("User-Controlled Input Reflected in HTML Response","LOW","Medium","Input Reflection",page["url"],"A harmless marker supplied in a query parameter was reflected in the response. This does not prove XSS.",f"Parameter {name} reflected marker {marker}.","Unsafe output handling could become an issue depending on context and encoding.","Manually review output context and ensure context-appropriate encoding.",parameter=name,owasp="A03 Injection",cwe="CWE-79"))
            except Exception: pass
            mod=qs.copy(); mod[idx]=(name,"'"); u=urlunparse(p._replace(query=urlencode(mod)))
            try:
                r,b,_,_=await client.get(u); text=b.decode(r.encoding or "utf-8",errors="replace")
                if any(re.search(pat,text,re.I) for pat in ERROR_PATTERNS): self.add(finding("Potential SQL-Related Error Handling Issue","MEDIUM","Medium","Injection",page["url"],"A non-destructive input variation caused a response matching a database error pattern. This is not confirmation of SQL injection.",f"Parameter {name} produced a recognizable database/error signature; response redacted.","Verbose database errors can expose internals and may indicate unsafe input handling.","Review parameter handling with authorized manual testing and use parameterized queries.",parameter=name,owasp="A03 Injection",cwe="CWE-89"))
            except Exception: pass
    async def special_files(self,client,target):
        for path in ["/robots.txt","/sitemap.xml","/.well-known/security.txt","/.git/HEAD","/.env"]:
            try:
                r,b,_,final=await client.get(urljoin(target,path)); text=b.decode(r.encoding or "utf-8",errors="replace")
                if r.status_code==200 and path in {"/.git/HEAD","/.env"}:
                    self.add(finding("Potential Sensitive Development Artifact Exposed","HIGH","High","Sensitive Exposure",final,"A commonly misplaced development artifact is publicly reachable.",f"{path} returned HTTP 200; body contents are not stored.","Exposed configuration or repository metadata can reveal secrets or source history.","Remove public access to development artifacts and rotate any exposed secrets.",owasp="A05 Security Misconfiguration"))
                elif path=="/.well-known/security.txt" and r.status_code!=200: self.add(finding("security.txt Not Available","INFO","Confirmed","Security Metadata",final,"No reachable security.txt file was observed.",f"HTTP {r.status_code}","This does not create a direct vulnerability but may make coordinated disclosure harder.","Consider publishing /.well-known/security.txt."))
            except Exception: pass
    async def run(self):
        scan=self.db.get(Scan,self.scan_id); started=time.perf_counter(); scan.status="running"; self.db.commit()
        try:
            await self.emit("validating",msg="Validating target and scope")
            target=await validate_public_target(self.config["target"],allow_demo_private=self.demo)
            client=SafeHttpClient(target,self.config.get("concurrency",5),self.config.get("follow_redirects",True),allow_demo_private=self.demo)
            await self.emit("tls",msg="Checking TLS")
            if not self.demo: await self.tls_check(target)
            crawler=Crawler(client,self.config.get("max_pages",25),self.config.get("max_depth",2))
            pages=await crawler.crawl(target,self.emit)
            await self.emit("analyzing",0,len(pages),"Analyzing responses")
            for i,page in enumerate(pages,1):
                self.db.add(Page(scan_id=self.scan_id,**{k:page[k] for k in ["url","status_code","content_type","response_time","response_size","title","depth"]}))
                self.db.add(RequestRecord(scan_id=self.scan_id,url=page["url"],method="GET",status_code=page["status_code"],response_time=page["response_time"],response_length=page["response_size"],content_type=page["content_type"],headers_json=json.dumps({k:("************" if k.lower() in {"set-cookie","cookie","authorization","proxy-authorization"} else redact(v)) for k,v in page["headers"].items()})))
                for f in headers_check.check(page["url"],page["headers"],page["url"].startswith("https://"))+cookies_check.check(page["url"],page["headers"],page["url"].startswith("https://"))+cors_check.check(page["url"],page["headers"]): self.add(f)
                if "text/html" in page["content_type"]:
                    text=page["body"].decode("utf-8",errors="replace"); fs,soup=analyze_html(page["url"],text,page["headers"])
                    for f in fs:self.add(f)
                    if self.config.get("scan_javascript",True):
                        for s in soup.find_all("script",src=True)[:10]:
                            jsurl=urljoin(page["url"],s["src"])
                            if same_host(target,jsurl):
                                try:
                                    r,b,_,_=await client.get(jsurl)
                                    if len(b)<=settings.max_js_bytes:
                                        for f in js_check(jsurl,b.decode(r.encoding or "utf-8",errors="replace")): self.add(f)
                                        if r.status_code==200 and jsurl.endswith(".js"):
                                            try:
                                                mr,mb,_,_=await client.get(jsurl+".map")
                                                if mr.status_code==200 and len(mb)>20:self.add(finding("Source Map Publicly Accessible","LOW","High","JavaScript",jsurl+".map","A JavaScript source map appears publicly accessible.",".map request returned HTTP 200.","Source maps may reveal original source structure and internal names.","Disable production source maps or restrict access if they expose sensitive internals."))
                                            except Exception: pass
                                except Exception: pass
                    await self.safe_parameter_checks(client,page)
                await self.emit("analyzing",i,len(pages),f"Analyzed {i}/{len(pages)} pages")
            await self.special_files(client,target)
            await client.close()
            scan.pages_scanned=len(pages); scan.requests_sent=client.requests_sent; scan.security_score=calculate_score(self.findings); scan.status="completed"; scan.completed_at=datetime.utcnow(); scan.duration=time.perf_counter()-started; self.db.commit()
            await self.emit("completed",len(pages),len(pages),"Scan completed")
        except Exception as exc:
            scan.status="failed"; scan.error=redact(str(exc)); scan.duration=time.perf_counter()-started; self.db.commit(); await self.emit("failed",msg=str(exc))
