#!/usr/bin/env python3
"""Actual CLI/MCP/plugin/mock-model smoke checks against a built application."""
import argparse,hashlib,http.server,json,os,pathlib,subprocess,tempfile,threading
p=argparse.ArgumentParser();p.add_argument('--profile',default='release');args=p.parse_args()
root=pathlib.Path(__file__).resolve().parent.parent
bin_dir=root/'target'/args.profile
with tempfile.TemporaryDirectory(prefix='raven-smoke-') as tmp:
    tmp=pathlib.Path(tmp);database=tmp/'db.sqlite';fixture=root/'fixtures/sample'
    if not fixture.is_file():
        subprocess.run(['cc', '-O0', '-g', str(root/'fixtures/sample.c'), '-o', str(fixture)], check=True)
    def cli(*args, env=None):
        r=subprocess.run([str(bin_dir/'raven'),'--database',str(database),*map(str,args)],capture_output=True,text=True,env=env,check=True)
        return json.loads(r.stdout)
    analysis=cli('analyze',fixture)
    assert analysis['sha256']==hashlib.sha256(fixture.read_bytes()).hexdigest()
    fun=next(f for f in analysis['functions'] if 'transform' in f['name'])
    address=hex(fun['address'])
    def call(tool,**kwargs):return cli('call','--file',fixture,tool,json.dumps(kwargs))
    instructions=cli('disasm',fixture,address,'--size','32');assert instructions and instructions[0]['address']==fun['address']
    function=cli('function',fixture,address);assert function['blocks'] and function['instructions']
    ann=call('annotate',address=address,name='fixture_transform',expected_revision=0);assert ann['revision']==1
    assert call('annotations')[0]['name']=='fixture_transform'
    call('signature_save',address=address,size=16,name='transform')
    assert call('signature_match',address=address,size=16)['match']['name']=='transform'
    triage=cli('triage',fixture);assert 'https://example.invalid/triage' in triage['iocs']['url']['values']
    batch=cli('batch',fixture,tmp/'missing');assert [r['ok'] for r in batch['results']]==[True,False]
    report=tmp/'report.json';call('save_report',path=str(report));assert json.loads(report.read_text())['analysis']['sha256']==analysis['sha256']
    manifest=tmp/'plugin.json';manifest.write_text(json.dumps({'name':'section-stats','version':'1','executable':'/usr/bin/python3','args':[str(root/'examples/plugin.py')]}))
    plugin=call('run_plugin',manifest=str(manifest));assert plugin['section_count']==len(analysis['sections'])
    received=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
            body=json.dumps({'choices':[{'message':{'content':'mock explanation: no runtime evidence'}}]}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*a):pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        env=dict(os.environ,RAVEN_ASSIST_URL=f'http://127.0.0.1:{server.server_port}/v1/chat/completions',RAVEN_ASSIST_MODEL='smoke-model')
        answer=cli('assist',fixture,'Explain this function','--address',address,env=env)
        assert answer['answer']=='mock explanation: no runtime evidence'
        assert received[0]['model']=='smoke-model' and address[2:] not in received[0]['model']
    finally:server.shutdown();server.server_close()
    requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
              {'jsonrpc':'2.0','method':'notifications/initialized'},
              {'jsonrpc':'2.0','id':2,'method':'tools/list'},
              {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'open_binary','arguments':{'path':str(fixture)}}},
              {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'disassemble','arguments':{'address':address,'size':32}}}]
    proc=subprocess.run([str(bin_dir/'raven-mcp'),'--database',str(database)],input='\n'.join(map(json.dumps,requests))+'\n',capture_output=True,text=True,check=True)
    responses=list(map(json.loads,proc.stdout.splitlines()));assert len(responses)==4
    assert len(responses[1]['result']['tools'])==25 and responses[-1]['result']['isError'] is False
    print(json.dumps({'status':'passed','format':analysis['format'],'architecture':analysis['architecture'],'sha256':analysis['sha256'],'functions':len(analysis['functions']),'mcp_tools':25,'checks':['actual CLI analysis/disassembly/CFG','annotations reopen','exact signatures','triage IOC','batch mixed success','JSON report','process plugin','local mock Assist HTTP','MCP stdio lifecycle + real disassembly']},indent=2))
