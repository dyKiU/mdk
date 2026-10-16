#!/usr/bin/env python3
"""Remote-only genuine Catalog Body blocking witness; never SDK qualification."""
import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
import time
from upstream_completion_ci import compile_cases, ensure, environment, freeze, identity, parse_body
from verify_upstream_completion_candidate_source import normalize

BASE='ac3db2d82bdca105d249b7ddfba73734b4e153e9'
CASE='held_automatic_catalog_body_keeps_fresh_account_commands_responsive'
FILE='crates/marmot-app/src/native_device_linking/tests/automatic_pairing_acceptance.rs'
NAME='native_device_linking::automatic_pairing_acceptance::'+CASE
MESSAGE='held automatic Catalog Body must not block a fresh account actor command'
RUST=[FILE,'crates/marmot-app/src/client/account_chat_sharing/automatic.rs','crates/marmot-app/src/relay_plane/mod.rs']
SELF='scripts/qualify_upstream_automatic_body.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
STAGES=['bilateral-pair-and-history-ready','prehold-control','actual-new-chat-catalog-body-held','peer-progress-control','fresh-command-verdict-frozen','actual-body-released','same-fresh-command-completed','actual-new-chat-delivered-once','positive-runtime-close','positive-runtime-close']

def expected_panic():
    lines=Path(FILE).read_text().splitlines()
    matches=[index for index,line in enumerate(lines) if MESSAGE in line]
    ensure(len(matches)==1,'unique-body-responsiveness-assertion')
    line=max(index for index in range(matches[0]+1) if re.search(r'\bassert!\s*\(',lines[index]))+1
    return {'file':FILE,'line':line}

def parse(raw):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    row=parse_body(raw,CASE)
    row['named_cases']=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.',raw)
    row['expected_panic']=expected_panic()
    row['named_assertion_observed']=MESSAGE in raw
    events=[]; malformed=0
    for line in raw.splitlines():
        if not line.startswith('automatic-body-control'): continue
        match=re.fullmatch(r'automatic-body-control stage=([a-z-]+)(?: responsive=(true|false)| index=([01]))?',line)
        if not match: malformed+=1; continue
        events.append({'stage':match[1],'responsive':None if match[2] is None else match[2]=='true','index':None if match[3] is None else int(match[3])})
    row['events']=events[:16]; row['malformed_or_excess_events']=malformed+max(len(events)-16,0)
    valid=[event['stage'] for event in events]==STAGES and not row['malformed_or_excess_events']
    if valid:
        valid=all(event['responsive'] is None and event['index'] is None for index,event in enumerate(events) if index not in [4,8,9])
        valid &= events[4]['responsive'] is not None and events[4]['index'] is None
        valid &= all(events[index]['responsive'] is None and events[index]['index']==index-8 for index in [8,9])
    row['all_prerequisites_and_two_positive_closes']=bool(valid)
    row['responsive_while_held']=events[4]['responsive'] if valid else None
    return row

def intended_red(row):
    locations=row.get('panic_locations',[])
    return row.get('body_exit_code')==101 and row.get('passed')==0 and row.get('failed')==1 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('named_cases')==[NAME] and row.get('all_panic_header_count')==1 and len(locations)==1 and all(locations[0][key]==value for key,value in row['expected_panic'].items()) and row.get('named_assertion_observed') and row.get('all_prerequisites_and_two_positive_closes') and row.get('responsive_while_held') is False and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')

def parser_preflight():
    panic=expected_panic()
    events=['automatic-body-control stage='+stage+(' responsive=false' if index==4 else ' index='+str(index-8) if index in [8,9] else '') for index,stage in enumerate(STAGES)]
    raw='test '+NAME+' ... FAILED\n'+'\n'.join(events)+'\nthread case panicked at '+FILE+':'+str(panic['line'])+':5:\n'+MESSAGE+'\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;'
    row=dict(parse(raw),body_exit_code=101)
    ensure(intended_red(row),'body-runtime-red-parser-positive')
    negatives=0
    changes=[{'body_exit_code':0},{'body_exit_code':1},{'passed':1},{'failed':0},{'ignored':1},{'executed_nonignored':0},{'all_panic_header_count':2},{'named_cases':[]},{'named_cases':[NAME+'other']},{'named_assertion_observed':False},{'watchdog_triggered':True},{'actual_count_unknown':True},{'responsive_while_held':True},{'panic_locations':[dict(panic,line=panic['line']+1,column=1)]}]
    for change in changes:
        ensure(not intended_red(dict(row,**change)),'body-nonbehavioral-or-unrelated-red-negative'); negatives+=1
    for index in range(len(events)):
        changed=raw.replace(events[index]+'\n','',1)
        ensure(not intended_red(dict(parse(changed),body_exit_code=101)),'body-missing-prerequisite-negative'); negatives+=1
    for changed in [raw+'\nautomatic-body-control unknown',raw+'\n'+events[0],raw.replace('index=1','index=0'),raw.replace('responsive=false','responsive=true'),raw.replace(events[1]+'\n'+events[2],events[2]+'\n'+events[1])]:
        ensure(not intended_red(dict(parse(changed),body_exit_code=101)),'body-malformed-duplicate-or-reordered-negative'); negatives+=1
    return {'positive_controls':1,'negative_controls':negatives,'actual_product_bodies':0}

def preflight():
    changed=subprocess.check_output(['git','diff','--name-only',BASE],text=True).splitlines()
    ensure(set(changed)<=set(RUST+[SELF,WORKFLOW]),'body-unexpected-source-change')
    counts={}; pattern=r'(?m)^[ \t]*// AUTOMATIC_BODY_TEST_BEGIN\n.*?^[ \t]*// AUTOMATIC_BODY_TEST_END\n'
    for name in RUST:
        text=Path(name).read_text(); original=subprocess.check_output(['git','show',BASE+':'+name],text=True)
        blocks=re.findall(pattern,text,re.S|re.M); counts[name]=len(blocks)
        ensure(blocks and text.count('AUTOMATIC_BODY_TEST_BEGIN')==text.count('AUTOMATIC_BODY_TEST_END')==len(blocks),'body-hook-marker-bounds')
        ensure(normalize(re.sub(pattern,'',text,flags=re.S|re.M))==normalize(original),'body-original-token-or-string-drift')
    ast.parse(Path(SELF).read_text(),filename=SELF)
    report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'original_four_controls_and_product_tokens_exact_after_strip':True,'hook_blocks':counts,'parser_preflight':parser_preflight(),'actual_product_bodies':0,'qualification_passed':False}
    Path('automatic-body-source.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

def run_red():
    out=Path('automatic-body-evidence'); out.mkdir(exist_ok=True)
    report=environment(); report.update(scope='one genuine automatic Catalog Body actor responsiveness baseline; independent of enrollment timeout cause',qualification_passed=False,intended_behavioral_red=False)
    def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    frozen=freeze(); report['source_before_sha256']=identity(frozen); save()
    try:
        report['source_preflight']=preflight(); compilation,cases=compile_cases([CASE]); report['compilation']=compilation; save()
        ensure(freeze()==frozen,'body-compile-input-drift')
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') and len(cases)==1,'body-compile-or-inventory-not-qualified')
        case=cases[CASE]; started=time.monotonic(); row={'test':case['name'],'binary_sha256':case['binary_sha256']}
        report['body']=row; save()
        try:
            result=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
            raw=result.stdout+result.stderr; row.update(body_exit_code=result.returncode)
        except subprocess.TimeoutExpired as error:
            def text(value): return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            raw=text(error.stdout)+text(error.stderr); row.update(watchdog_triggered=True,actual_count_unknown=True)
        row['body_seconds']=time.monotonic()-started; save()
        try: row.update(parse(raw))
        except Exception as error:
            row['parser_exception']=type(error).__name__; save(); raise
        save()
        report['intended_behavioral_red']=bool(intended_red(row))
    except Exception as error: report['controller_exception']=type(error).__name__
    finally:
        report['inputs_pristine']=freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
        report['source_after_sha256']=identity(freeze()); save()
    raise SystemExit(0 if report['intended_behavioral_red'] and report['inputs_pristine'] else 1)

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--mode',choices=['preflight','red'],required=True); args=parser.parse_args()
    if args.mode=='preflight': preflight()
    else: run_red()
