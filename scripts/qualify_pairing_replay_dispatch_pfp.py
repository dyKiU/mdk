#!/usr/bin/env python3
"""Remote-only three-unit selector P/F/P; never protocol or native qualification."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import qualify_upstream_storage_boundary as bounded

SELF='scripts/qualify_pairing_replay_dispatch_pfp.py'
TEST='scripts/test_pairing_replay_dispatch.py'
TEST_SHA='0d39a7bc01f5e0384a653f9dd1bcf2b26312db5c82b4dcfaf18f1186dc895c3e'  # Exact reviewed union including the isolated negative Body route.
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
OUT=Path('pairing-dispatch-pfp-evidence')
NAMES=['test_every_scope_executes_its_exact_inventory_and_bounded_command',
       'test_every_scope_is_offered_and_routes_to_pairing_job',
       'test_explicit_replay_alias_preserves_the_existing_one_case_scope']
TARGET=NAMES[1]
RESTART=['pairing-restart-diagnostic','pairing-restart-higher-source']
REPLAY={'pairing-replay-regression','pairing-diagnostic','pairing-consent-fairness',*RESTART,'automatic-body-regression','automatic-body-negative'}
ASSERTION='self.assertTrue(set(routed) <= set(supported))'
ensure=bounded.ensure

def digest(data):return hashlib.sha256(data).hexdigest()
def identity(values):return digest(json.dumps(values,sort_keys=True).encode())

def event_identity(kind,repo,event,head,event_sha):
    ensure(repo=='dyKiU/mdk' and re.fullmatch('[0-9a-f]{40}',head) and re.fullmatch('[0-9a-f]{40}',event_sha),'approved-repository-and-full-source-SHAs')
    ensure(event.get('repository',{}).get('full_name')==repo,'event-repository')
    if kind=='pull_request':
        request=event.get('pull_request',{});source=request.get('head',{})
        ensure(source.get('sha')==head and source.get('repo',{}).get('full_name')==repo
            and request.get('base',{}).get('repo',{}).get('full_name')==repo,'exact-approved-PR-checkout-head')
    else:
        ensure(kind in {'push','workflow_dispatch'} and event_sha==head,'exact-push-or-dispatch-checkout')
        if kind=='push':ensure(event.get('after')==head,'push-after-identity')
    return {'event':kind,'source':head,'event_sha':event_sha,'event_SHA_equals_checkout':event_sha==head,
        'PR_head_used_instead_of_assuming_merge_SHA':kind=='pull_request'}

def freeze():
    result={}
    for entry in subprocess.check_output(['git','ls-files','--stage','-z']).split(b'\0'):
        if not entry:continue
        metadata,path=entry.split(b'\t',1);mode,_,stage=metadata.decode().split();name=os.fsdecode(path);file=Path(name)
        ensure(stage=='0' and mode in {'100644','100755','120000'},'ordinary-tracked-layout')
        bits=file.lstat().st_mode;link=file.is_symlink()
        ensure((mode=='120000')==link and (link or stat.S_ISREG(bits)),'ordinary-tracked-source-kind')
        result[name]={'git_mode':mode,'mode':stat.S_IMODE(bits),'symlink':link,
            'sha256':digest(os.fsencode(os.readlink(file)) if link else file.read_bytes())}
    return result

def condition(text,job):
    header='  '+job+':\n';ensure(text.count(header)==1,'unique-job-header')
    section=text.split(header,1)[1].split('    name:',1)[0]
    lines=[line for line in section.splitlines(True) if line.startswith('    if: ')]
    ensure(len(lines)==1,'unique-job-condition')
    found=re.search(r"fromJSON\('(\[[^'\n]+\])'\)",lines[0]);ensure(found is not None,'closed-job-route-list')
    values=json.loads(found[1]);ensure(isinstance(values,list) and len(values)==len(set(values))
        and all(type(v) is str and re.fullmatch('[a-z0-9-]{1,80}',v) for v in values),'distinct-closed-scope-list')
    return lines[0],found,values

def mutant(text):
    line,found,values=condition(text,'workflow-union-preflight')
    ensure(all(values.count(scope)==1 for scope in RESTART),'both-new-dependency-scopes-required')
    _,_,replay=condition(text,'pairing-replay');ensure(set(replay)==REPLAY,'unchanged-exact-seven-replay-routes')
    replacement=line[:found.start(1)]+json.dumps([v for v in values if v not in RESTART],separators=(',',':'))+line[found.end(1):]
    ensure(text.count(line)==1 and replacement!=line,'one-narrow-dependency-list-mutation')
    changed=text.replace(line,replacement,1)
    ensure(condition(changed,'pairing-replay')[0]==condition(text,'pairing-replay')[0],'replay-list-unchanged-by-mutant')
    return changed

def assertion_line():
    sites=[i for i,line in enumerate(Path(TEST).read_text().splitlines(),1) if line.strip()==ASSERTION]
    ensure(len(sites)==1,'unique-original-dependency-assertion');return sites[0]

def parse(raw,code):
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    rows=[];unknown=0
    for line in clean.splitlines():
        if not line.startswith('test_'):continue
        found=re.fullmatch(r'(test_[a-z0-9_]+) \(__main__\.PairingReplayDispatchTests(?:\.(test_[a-z0-9_]+))?\) \.\.\. (ok|FAIL|ERROR|skipped.*|expected failure|unexpected success)',line)
        if found and found[1] in NAMES and (found[2] is None or found[2]==found[1]):rows.append({'name':found[1],'status':'skipped' if found[3].startswith('skipped') else found[3]})
        else:unknown+=1
    summaries=re.findall(r'(?m)^Ran ([0-9]{1,3}) tests? in [0-9]+(?:\.[0-9]+)?s$',clean)
    observed=len(rows);complete=(unknown==0 and len(summaries)==1 and int(summaries[0])==observed
        and observed==3 and {r['name'] for r in rows}==set(NAMES) and len({r['name'] for r in rows})==3
        and all(r['status'] in {'ok','FAIL','ERROR','skipped'} for r in rows))
    partial={'passed':sum(r['status']=='ok' for r in rows),'failed':sum(r['status']=='FAIL' for r in rows),
        'errors':sum(r['status']=='ERROR' for r in rows),'skipped':sum(r['status'].startswith('skipped') for r in rows)}
    failure_headers=re.findall(r'(?m)^FAIL: (test_[a-z0-9_]+) \(__main__\.PairingReplayDispatchTests(?:\.(test_[a-z0-9_]+))?\)$',clean)
    sites=re.findall(r'(?m)^  File "[^"\n]*scripts/test_pairing_replay_dispatch\.py", line ([0-9]{1,6}), in ([a-z0-9_]+)$',clean)
    own_line=assertion_line()
    row={'exit_code':code,'actual_counts_complete':complete,'cases':rows,'unknown_header_count':unknown,'known_partial_counts':partial,
        'passed':partial['passed'] if complete else None,'failed':partial['failed'] if complete else None,
        'errors':partial['errors'] if complete else None,'skipped':partial['skipped'] if complete else None,
        'executed':observed if complete else None,'summary_test_count':int(summaries[0]) if len(summaries)==1 else None,
        'green_summary_count':len(re.findall(r'(?m)^OK$',clean)),
        'intended_failure_summary_count':len(re.findall(r'(?m)^FAILED \(failures=1\)$',clean)),
        'failure_header_count':len(re.findall(r'(?m)^FAIL: ',clean)),'error_header_count':len(re.findall(r'(?m)^ERROR: ',clean)),
        'intended_failure_header':failure_headers==[(TARGET,TARGET)] or failure_headers==[(TARGET,'')],
        'exact_dependency_assertion_site':sites==[(str(own_line),TARGET)],
        'exact_dependency_assertion_source_count':sum(line.strip()==ASSERTION for line in clean.splitlines()),
        'exact_false_assertion_payload_count':len(re.findall(r'(?m)^AssertionError: False is not true$',clean)),
        'unexpected_failure_or_error_header_count':len(re.findall(r'(?m)^(?:FAIL|ERROR): ',clean))-len(failure_headers)}
    return row

def green(row):
    return row.get('actual_counts_complete') is True and all(type(row.get(k)) is int and row[k]==v for k,v in
        {'exit_code':0,'passed':3,'failed':0,'errors':0,'skipped':0,'executed':3,'green_summary_count':1,
         'intended_failure_summary_count':0,'failure_header_count':0,'error_header_count':0,'exact_false_assertion_payload_count':0,'unexpected_failure_or_error_header_count':0}.items())

def intended(row):
    return (row.get('actual_counts_complete') is True and all(type(row.get(k)) is int and row[k]==v for k,v in
        {'exit_code':1,'passed':2,'failed':1,'errors':0,'skipped':0,'executed':3,'green_summary_count':0,
         'intended_failure_summary_count':1,'failure_header_count':1,'error_header_count':0,'exact_dependency_assertion_source_count':1,
         'exact_false_assertion_payload_count':1,'unexpected_failure_or_error_header_count':0}.items())
        and row.get('intended_failure_header') is True and row.get('exact_dependency_assertion_site') is True
        and all((case['status']=='FAIL')==(case['name']==TARGET) for case in row['cases']))

def parser_controls():
    prefix=''.join(name+' (__main__.PairingReplayDispatchTests.'+name+') ... '+('FAIL' if name==TARGET else 'ok')+'\n' for name in NAMES)
    bad=prefix+'\nFAIL: '+TARGET+' (__main__.PairingReplayDispatchTests.'+TARGET+')\nTraceback (most recent call last):\n  File "/public/scripts/test_pairing_replay_dispatch.py", line '+str(assertion_line())+', in '+TARGET+'\n    '+ASSERTION+'\nAssertionError: False is not true\n\nRan 3 tests in 1.234s\n\nFAILED (failures=1)\n'
    good=''.join(name+' (__main__.PairingReplayDispatchTests.'+name+') ... ok\n' for name in NAMES)+'\nRan 3 tests in 1.234s\n\nOK\n'
    ensure(green(parse(good,0)) and intended(parse(bad,1)),'closed-unittest-positive-controls')
    negatives=[bad.replace('line '+str(assertion_line()),'line '+str(assertion_line()+1)),bad.replace(ASSERTION,'self.assertTrue(False)'),
        bad.replace('False is not true','private payload'),bad.replace(' ... FAIL',' ... ERROR'),bad.replace('Ran 3 tests','Ran 0 tests'),
        bad+bad,bad.replace(TARGET,'test_foreign'),bad.replace(' ... ok',' ... skipped reason',1),bad.replace('failures=1','failures=2')]
    for raw in negatives:ensure(not intended(parse(raw,1)),'unittest-adversary-rejected')
    ensure(not intended(parse(bad,0)) and not green(parse(good,1)),'exact-exit-controls')
    ensure(not green(parse(good+'FAIL: '+TARGET+' (__main__.PairingReplayDispatchTests.'+TARGET+')\n',0)),'foreign-failure-header-never-GREEN')
    repo={'full_name':'dyKiU/mdk'};head='1'*40;merge='2'*40
    event={'repository':repo,'pull_request':{'head':{'sha':head,'repo':repo},'base':{'repo':repo}}}
    ensure(event_identity('pull_request','dyKiU/mdk',event,head,merge)['event_SHA_equals_checkout'] is False,'real-PR-head-not-merge-control')
    return {'positive':3,'negative':len(negatives)+3,'actual_unittest_executions':0,'compiler_or_protocol_bodies':0}

def fresh_write(path,data,mode):
    ensure(not path.is_symlink() and (not path.exists() or path.is_file()),'owned-workflow-path')
    previous=path.stat().st_mtime_ns if path.exists() else 0;path.write_bytes(data);os.chmod(path,mode)
    now=max(time.time_ns(),previous+1);os.utime(path,ns=(now,now))

def phase(label,expected,save,report):
    row={'label':label,'verified':False};report['phases'].append(row);save()
    try:
        ensure(freeze()==expected,'before-unittest-whole-source-pristine')
        code,raw,seconds=bounded.capture([sys.executable,TEST,'-v'],120,limit=256*1024)
        row['body']=parse(raw,code);row['seconds']=seconds;save()
        row['verified']=(intended if label=='mutant' else green)(row['body'])
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';raise
    finally:
        row['source_after_sha256']=identity(freeze());row['inputs_pristine']=freeze()==expected
        row['verified']=row['verified'] and row['inputs_pristine'];save()
    return row

def totals(phases):
    rows=[p['body'] for p in phases if 'body' in p]
    keys=['passed','failed','errors','skipped','executed']
    return {'actual_'+key:sum(r[key] for r in rows) if len(rows)==3 and all(type(r.get(key)) is int for r in rows) else None for key in keys} | {
        'known_partial_counts':{key:sum(r[key] for r in rows if type(r.get(key)) is int) for key in keys},
        'unknown_or_unexecuted_phase_count':3-sum(all(type(r.get(key)) is int for key in keys) for r in rows)}

def main():
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'selector_PFP_verified':False,'evidence_kind':'executed_metadata_unittests_with_temporary_stub_Cargo',
        'real_GitHub_mutant_dispatch_performed':False,'protocol_qualification':False,'native_qualification':False,'compiler_bodies':0,'protocol_bodies':0,'automatic_retries':0,'phases':[]}
    before=original=mode=None;path=Path(WORKFLOW)
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
        report['source_guard']=event_identity(os.environ.get('GITHUB_EVENT_NAME'),os.environ.get('GITHUB_REPOSITORY'),json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()),head,os.environ.get('GITHUB_SHA',''))
        ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_WORKFLOW_REF','').startswith('dyKiU/mdk/'+WORKFLOW+'@'),'hosted-exact-workflow-path')
        ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-GitHEAD-pristine')
        ensure(isinstance(TEST_SHA,str) and re.fullmatch('[0-9a-f]{64}',TEST_SHA) and digest(Path(TEST).read_bytes())==TEST_SHA,'frozen-unchanged-three-unit-fixture')
        report['parser_controls']=parser_controls();before=freeze();original=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
        changed=mutant(original.decode()).encode();report['source_before_sha256']=identity(before);save()
        baseline=phase('baseline',before,save,report);ensure(baseline['verified'],'fresh-three-metadata-controls-before-mutation')
        try:
            fresh_write(path,changed,mode);expected=freeze()
            ensure(set(expected)==set(before) and {p for p in before if before[p]!=expected[p]}=={WORKFLOW},'only-owned-preflight-list-changed')
            mutation=phase('mutant',expected,save,report)
        finally:
            if path.is_symlink():path.unlink()
            fresh_write(path,original,mode);restored=phase('restored',before,save,report)
        report.update(totals(report['phases']))
        report['selector_PFP_verified']=(all(p['verified'] for p in [baseline,mutation,restored])
            and all(type(report.get(k)) is int and report[k]==v for k,v in {'actual_passed':8,'actual_failed':1,'actual_errors':0,'actual_skipped':0,'actual_executed':9}.items()))
        ensure(report['selector_PFP_verified'],'exact-nine-unit-PFP-required')
    except Exception as error:report['exception_type']=type(error).__name__;raise
    finally:
        active_exception=sys.exc_info()[0] is not None
        if original is not None:
            try:
                if path.is_symlink():path.unlink()
                if not path.is_file() or path.read_bytes()!=original or stat.S_IMODE(path.stat().st_mode)!=mode:fresh_write(path,original,mode)
            except Exception as error:
                report['restoration_exception_type']=type(error).__name__;report['selector_PFP_verified']=False
            try:
                final=freeze();report['inputs_pristine']=final==before;report['source_final_sha256']=identity(final)
            except Exception as error:
                report['inputs_pristine']=False;report['final_snapshot_exception_type']=type(error).__name__
            if not report['inputs_pristine']:report['selector_PFP_verified']=False
        report.update(totals(report['phases']))
        save()
        if original is not None and not active_exception:
            ensure(report['inputs_pristine'] and report['selector_PFP_verified'],'final-source-mode-restoration-and-PFP-required')

if __name__=='__main__':main()
