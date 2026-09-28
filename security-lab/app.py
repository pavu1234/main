from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

app=FastAPI(title='WebGuard Local Security Lab')

@app.get('/',response_class=HTMLResponse)
def home(q:str=''):
    return f'''<!doctype html><html><head><title>Local Security Lab</title></head><body>
    <h1>WebGuard Local Security Lab</h1><p>This intentionally weak app must stay local.</p>
    <p>Reflection: {q}</p>
    <form method="post" action="/login"><input name="username"><input type="password" name="password"><button>Login</button></form>
    <a href="/?q=test">Reflection test</a><script src="/static/app.js"></script></body></html>'''

@app.post('/login')
def login():
    r=JSONResponse({'ok':False,'message':'demo only'})
    r.set_cookie('sessionid','demo-secret',httponly=False,secure=False)
    return r

@app.get('/error',response_class=PlainTextResponse)
def error():
    return 'Traceback (most recent call last):\n  File "/var/www/app.py", line 42\nsqlite3.OperationalError: no such table: demo'

@app.get('/static/app.js',response_class=PlainTextResponse)
def js():
    return 'const api="http://localhost:9000/api"; function render(x){document.getElementById("out").innerHTML=x;}'

@app.get('/robots.txt',response_class=PlainTextResponse)
def robots(): return 'User-agent: *\nDisallow: /admin-demo\n'

@app.get('/.env',response_class=PlainTextResponse)
def env(): return 'DEMO_KEY=sk_test_DEMOONLY12345678\n'

@app.get('/.git/HEAD',response_class=PlainTextResponse)
def git_head(): return 'ref: refs/heads/main\n'

@app.get('/cors')
def cors():
    return JSONResponse({'demo':True},headers={'Access-Control-Allow-Origin':'*','Access-Control-Allow-Credentials':'true'})
