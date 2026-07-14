from __future__ import annotations
import argparse,json,subprocess,sys
from pathlib import Path

def load(p): return json.loads(Path(p).read_text())
def normalise_observed(doc):
    out=[]
    for kind,key in [('kv-namespace','kv_namespaces'),('d1-database','d1_databases'),('r2-bucket','r2_buckets')]:
        for x in doc.get(key,[]): out.append({'kind':kind,'id':x.get('id') or x.get('uuid') or x.get('name'),'name':x.get('name') or x.get('title')})
    return out

def declared(manifest, bindings):
    claims={}
    for c in manifest.get('components',[]):
        if c.get('kind') in {'kv-namespace','d1-database','r2-bucket'}: claims.setdefault((c['kind'],c['name']),[]).append(c.get('name'))
    for worker, rows in bindings.items():
        for b in rows:
            claims.setdefault((b['kind'],b['resource']),[]).append(worker)
    return claims

def audit(manifest,bindings,observed):
    claims=declared(manifest,bindings); findings=[]; seen=set()
    for o in normalise_observed(observed):
        key=(o['kind'],o['name']); seen.add(key); owners=claims.get(key,[])
        if not owners: findings.append({'severity':'warning','type':'orphaned','resource':o})
        elif len(set(owners))>1: findings.append({'severity':'warning','type':'multiply-owned','resource':o,'owners':sorted(set(owners))})
    for (kind,name),owners in claims.items():
        if (kind,name) not in seen: findings.append({'severity':'error','type':'missing','resource':{'kind':kind,'name':name},'owners':sorted(set(owners))})
    return {'schema_version':'atlas-resource-audit/report/v1','summary':{'findings':len(findings),'observed':len(observed)},'findings':findings}

def render(report):
    lines=['# Atlas resource audit','',f"Findings: {len(report['findings'])}",'']
    for f in report['findings']: lines.append(f"- **{f['type']}** `{f['resource']['kind']}/{f['resource']['name']}`")
    return '\n'.join(lines)+'\n'

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument('--manifest',required=True); p.add_argument('--bindings',required=True); p.add_argument('--observed',required=True); p.add_argument('--json-out'); p.add_argument('--markdown-out'); a=p.parse_args(argv)
    report=audit(load(a.manifest),load(a.bindings),load(a.observed))
    if a.json_out: Path(a.json_out).write_text(json.dumps(report,indent=2)+'\n')
    if a.markdown_out: Path(a.markdown_out).write_text(render(report))
    if not a.json_out and not a.markdown_out: print(json.dumps(report,indent=2))
    return 1 if any(x['severity']=='error' for x in report['findings']) else 0
if __name__=='__main__': raise SystemExit(main())
