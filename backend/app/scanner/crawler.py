import asyncio
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse
from bs4 import BeautifulSoup
from .scope import same_host

class Crawler:
    def __init__(self, client, max_pages=25, max_depth=2): self.client=client; self.max_pages=max_pages; self.max_depth=max_depth
    def canon(self,u):
        u,_=urldefrag(u); p=urlparse(u); path=p.path or "/"; return p._replace(path=path,fragment="").geturl()
    async def crawl(self, root, progress=None):
        q=deque([(self.canon(root),0)]); seen=set(); pages=[]
        while q and len(pages)<self.max_pages:
            url,depth=q.popleft()
            if url in seen or depth>self.max_depth: continue
            seen.add(url)
            try: resp,body,elapsed,final=await self.client.get(url)
            except Exception: continue
            ctype=resp.headers.get("content-type","")
            title=""; links=[]
            if "text/html" in ctype:
                text=body.decode(resp.encoding or "utf-8",errors="replace"); soup=BeautifulSoup(text,"lxml")
                title=soup.title.get_text(strip=True)[:300] if soup.title else ""
                if depth<self.max_depth:
                    for a in soup.find_all("a",href=True):
                        nxt=self.canon(urljoin(final,a["href"]))
                        if nxt.startswith(("http://","https://")) and same_host(root,nxt) and nxt not in seen: links.append(nxt)
            pages.append({"url":final,"status_code":resp.status_code,"content_type":ctype,"response_time":elapsed,"response_size":len(body),"title":title,"depth":depth,"headers":resp.headers,"body":body,"links":links})
            for nxt in links: q.append((nxt,depth+1))
            if progress: await progress("crawling", len(pages), self.max_pages)
        return pages
