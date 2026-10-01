"""Offline Sigma importer. Default validates; --apply imports disabled definitions."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone
import yaml
from sigma.rule import SigmaRule
from sigma.conditions import ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression, ConditionValueExpression
from sigma.types import SigmaString, SigmaCasedString, SigmaNumber, SigmaBool, SigmaNull, SigmaExists, SigmaRegularExpression, SigmaCIDRExpression, SigmaCompareExpression, SigmaFieldReference, SigmaExpansion, SpecialChars

LEVELS = {'informational':'Informational','low':'Low','medium':'Medium','high':'High','critical':'Critical'}

def value(v):
    if isinstance(v, SigmaString):
        parts=[]
        for p in v.s:
            if isinstance(p,str): parts.append({'text':p})
            elif p == SpecialChars.WILDCARD_MULTI: parts.append({'wildcard':'*'})
            elif p == SpecialChars.WILDCARD_SINGLE: parts.append({'wildcard':'?'})
            else: raise ValueError('Unresolved Sigma placeholder')
        return {'kind':'string','parts':parts,'cased':isinstance(v,SigmaCasedString)}
    if isinstance(v,SigmaNull): return {'kind':'null'}
    if isinstance(v,SigmaExists): return {'kind':'exists','value':v.exists}
    if isinstance(v,SigmaNumber): return {'kind':'number','value':v.number}
    if isinstance(v,SigmaBool): return {'kind':'bool','value':v.boolean}
    if isinstance(v,SigmaRegularExpression): return {'kind':'regex','pattern':str(v.regexp),'flags':''.join(sorted(v.sigma_to_re_flag[f] for f in v.flags))}
    if isinstance(v,SigmaCIDRExpression): return {'kind':'cidr','value':v.cidr}
    if isinstance(v,SigmaCompareExpression): return {'kind':'compare','value':v.number.number,'operator':v.op.name}
    if isinstance(v,SigmaFieldReference): return {'kind':'field','field':v.field,'startsWith':v.starts_with,'endsWith':v.ends_with}
    if isinstance(v,SigmaExpansion): return {'kind':'expansion','values':[value(x) for x in v.values]}
    raise ValueError('Unsupported typed value: '+type(v).__name__)

def condition(c):
    for cls,op in [(ConditionAND,'and'),(ConditionOR,'or'),(ConditionNOT,'not')]:
        if isinstance(c,cls): return {'op':op,'args':[condition(a) for a in c.args]}
    if isinstance(c,ConditionFieldEqualsValueExpression): return {'op':'field','field':c.field,'value':value(c.value)}
    if isinstance(c,ConditionValueExpression): return {'op':'keyword','value':value(c.value)}
    raise ValueError('Unsupported condition: '+type(c).__name__)

def prepare(folder):
    rows=[]; seen=set()
    for p in sorted(folder.rglob('*')):
        if p.suffix.lower() not in ('.yaml','.yml'): continue
        raw=p.read_bytes()
        if len(raw)>1024*1024: raise ValueError(f'{p}: file exceeds 1 MiB')
        d=yaml.safe_load(raw)
        if not isinstance(d,dict): raise ValueError(f'{p}: expected one YAML mapping')
        external=str(uuid.UUID(str(d.get('id',''))))
        if external in seen: raise ValueError(f'Duplicate external ID: {external}')
        seen.add(external)
        title=d.get('title'); level=d.get('level'); tags=d.get('tags',[])
        if not isinstance(title,str) or not title or len(title)>512: raise ValueError(f'{p}: invalid title')
        if level not in LEVELS: raise ValueError(f'{p}: unknown severity {level!r}')
        if not isinstance(tags,list) or any(not isinstance(t,str) for t in tags): raise ValueError(f'{p}: invalid tags')
        tag=tags[0] if tags else None
        if tag and len(tag)>255: raise ValueError(f'{p}: first tag exceeds 255 characters')
        definition={'format':'sigma','compilerVersion':1,'pySigmaVersion':importlib.metadata.version('pysigma'),
            'sourceFile':p.relative_to(folder).as_posix(),'sourceSha256':hashlib.sha256(raw).hexdigest(),
            'logsource':d.get('logsource',{}),'detection':d.get('detection'), 'tags':tags,
            'description':d.get('description',''),'falsepositives':d.get('falsepositives',[]),'sigmaStatus':d.get('status'),'references':d.get('references',[]),'status':'Unsupported','reason':None,'compiled':None}
        try:
            rule=SigmaRule.from_yaml(raw.decode('utf-8-sig'))
            definition['compiled']={'op':'or','args':[condition(c.parsed) for c in rule.detection.parsed_condition]}
            definition['status']='Compiled'
        except Exception as e: definition['reason']=f'{type(e).__name__}: {e}'[:1000]
        if 'correlation' in d: definition['correlation']=d['correlation']
        rows.append((external,title,LEVELS[level],tag,json.dumps(definition,ensure_ascii=False,default=str)))
    if not rows: raise ValueError('No YAML files found')
    return rows

def apply(rows,config):
    import pymysql
    with pymysql.connect(**config,charset='utf8mb4',autocommit=False) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT GET_LOCK('incident-platform-sigma-import',10)")
            if cur.fetchone()[0]!=1: raise RuntimeError('Another rule import is active')
            try:
                now=datetime.now(timezone.utc).replace(tzinfo=None)
                for row in rows:
                    cur.execute('''INSERT INTO DetectionRules
                        (ExternalRuleId,Title,Severity,ReferenceTag,DefinitionJson,Enabled,CreatedAt,UpdatedAt)
                        VALUES (%s,%s,%s,%s,%s,0,%s,%s)
                        ON DUPLICATE KEY UPDATE Title=VALUES(Title),Severity=VALUES(Severity),
                        ReferenceTag=VALUES(ReferenceTag),DefinitionJson=VALUES(DefinitionJson),Enabled=0,UpdatedAt=VALUES(UpdatedAt)''',(*row,now,now))
                conn.commit()
                cur.execute('SELECT COUNT(*),SUM(Enabled) FROM DetectionRules')
                print(json.dumps({'storedRows':cur.fetchone()},default=str))
                cur.execute('SELECT ExternalRuleId,Title,Severity,Enabled FROM DetectionRules ORDER BY Id LIMIT 5')
                print(json.dumps({'sampleRows':cur.fetchall()},ensure_ascii=False))
            except Exception:
                conn.rollback(); raise
            finally: cur.execute("SELECT RELEASE_LOCK('incident-platform-sigma-import')")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,default=Path('seed-rules'))
    parser.add_argument('--apply',action='store_true')
    parser.add_argument('--db-env',default='SIGMA_DB_JSON')
    parser.add_argument('--report',type=Path,default=Path('logs/sigma-import-report.json'))
    args=parser.parse_args()
    rows=prepare(args.folder)
    report=[{'externalId':r[0],'title':r[1],'severity':r[2],'enabled':False,
        **{k:json.loads(r[4])[k] for k in ('sourceFile','status','reason')}} for r in rows]
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print(json.dumps({'files':len(rows),'compiled':sum(r['status']=='Compiled' for r in report),'unsupported':sum(r['status']!='Compiled' for r in report),'applied':args.apply}))
    if args.apply: apply(rows,json.loads(os.environ[args.db_env]))

if __name__=='__main__': main()
