#!/usr/bin/env python3
"""Remote-only four-unit selector P/F/P; never protocol or native qualification."""
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
TEST_SHA='0ccb2dc827ef99a43b59b7a05ae6d0654983432ad62d6f44eded4457ef11a795'  # Exact controlled-mock four-method union; root aliases and nine routes retained.
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
OUT=Path('pairing-dispatch-pfp-evidence')
NAMES=['test_every_scope_executes_its_exact_inventory_and_bounded_command',
       'test_every_scope_is_offered_and_routes_to_pairing_job',
       'test_explicit_replay_alias_preserves_the_existing_one_case_scope',
       'test_departure_contention_rejects_a_serial_budget_before_cargo']
TARGET=NAMES[1]
RESTART=['pairing-restart-diagnostic','pairing-restart-higher-source']
REPLAY={'pairing-replay-regression','pairing-diagnostic','pairing-consent-fairness',*RESTART,'pairing-departure-contention','pairing-departure-staggered','automatic-body-regression','automatic-body-negative'}
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
    _,_,replay=condition(text,'pairing-replay');ensure(set(replay)==REPLAY,'unchanged-exact-nine-replay-routes')
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
        and observed==4 and {r['name'] for r in rows}==set(NAMES) and len({r['name'] for r in rows})==4
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
        {'exit_code':0,'passed':4,'failed':0,'errors':0,'skipped':0,'executed':4,'green_summary_count':1,
         'intended_failure_summary_count':0,'failure_header_count':0,'error_header_count':0,'exact_false_assertion_payload_count':0,'unexpected_failure_or_error_header_count':0}.items())

def intended(row):
    return (row.get('actual_counts_complete') is True and all(type(row.get(k)) is int and row[k]==v for k,v in
        {'exit_code':1,'passed':3,'failed':1,'errors':0,'skipped':0,'executed':4,'green_summary_count':0,
         'intended_failure_summary_count':1,'failure_header_count':1,'error_header_count':0,'exact_dependency_assertion_source_count':1,
         'exact_false_assertion_payload_count':1,'unexpected_failure_or_error_header_count':0}.items())
        and row.get('intended_failure_header') is True and row.get('exact_dependency_assertion_site') is True
        and all((case['status']=='FAIL')==(case['name']==TARGET) for case in row['cases']))

MOCK_ORDER_SOURCE_SHA='c7d7866d9e852cbe47287a81f7a6eedd7183379928942da576b7a599d7fbd718'
MOCK_ORDER_LINE=151
MOCK_ORDER_ASSERTION='self.assertIn("renewal", commands[0][commands[0].index("-E") + 1])'
MOCK_ORDER_SCOPE='pairing-departure-staggered'
MOCK_ORDER_DEPARTURE='package(marmot-app) & test(=native_device_linking::tests::automatic_account_departure_acceptance::account_departure_completes_when_source_branch_wins_same_epoch_race)'

def mock_order_diagnostic(raw,code,source_sha,source_assertion_at_site):
    # Independent finite metadata observation; NEVER called by green/intended/parse.
    clean=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
    name=NAMES[0];description=name+' (__main__.PairingReplayDispatchTests.'+name+')'
    subtest=description+" (scope='"+MOCK_ORDER_SCOPE+"')"
    lines=clean.splitlines()
    parent_count=sum(line.rstrip()==description+' ...' for line in lines)
    subtest_count=sum(line in {subtest+' ... FAIL','  '+subtest+' ... FAIL'} for line in lines)
    other_ok=sum(lines.count(other+' (__main__.PairingReplayDispatchTests.'+other+') ... ok') for other in NAMES[1:])
    allowed={description+' ...',subtest+' ... FAIL','  '+subtest+' ... FAIL'}|{other+' (__main__.PairingReplayDispatchTests.'+other+') ... ok' for other in NAMES[1:]}
    status_lines=[line for line in lines if re.match(r'^(?:  )?test_[A-Za-z0-9_]+ \(',line) and ' ...' in line]
    status_shape=(len(status_lines)==5 and all(line.rstrip() in allowed for line in status_lines)
        and all(lines.count(other+' (__main__.PairingReplayDispatchTests.'+other+') ... ok')==1 for other in NAMES[1:]))
    summaries=re.findall(r'(?m)^Ran ([0-9]{1,3}) tests? in [0-9]+(?:\.[0-9]+)?s$',clean)
    failure_headers=re.findall(r'(?m)^FAIL: [^\n]*$',clean)
    error_headers=re.findall(r'(?m)^ERROR: [^\n]*$',clean)
    failed_summaries=re.findall(r'(?m)^FAILED \([^\n]*\)$',clean)
    source_site=re.findall(r'(?m)^  File "(?:[^"\n]*/)?scripts/test_pairing_replay_dispatch\.py", line ([0-9]{1,5}), in '+re.escape(name)+r'$',clean)
    source_assert_count=sum(line.strip()==MOCK_ORDER_ASSERTION for line in lines)
    expected_payload="AssertionError: 'renewal' not found in '"+MOCK_ORDER_DEPARTURE+"'"
    payload_count=lines.count(expected_payload)
    assertion_payload_count=sum(line.startswith('AssertionError:') for line in lines)
    row={'diagnostic_kind':'controlled_staggered_mock_order_regression','source_test_sha_verified':source_sha==MOCK_ORDER_SOURCE_SHA,
        'source_assertion_literal_verified':source_assertion_at_site is True,'expected_source_site':{'file':TEST,'line':MOCK_ORDER_LINE},
        'exact_parent_header_count':parent_count,'exact_staggered_failed_subtest_status_count':subtest_count,
        'other_known_method_OK_count':other_ok,'strict_known_status_inventory':status_shape,
        'summary_test_count':int(summaries[0]) if len(summaries)==1 else None,
        'sole_exact_failed_subtest_header':failure_headers==['FAIL: '+subtest],
        'failure_header_count':len(failure_headers),'error_header_count':len(error_headers),
        'sole_failure_summary':failed_summaries==['FAILED (failures=1)'] and not re.search(r'(?m)^OK(?:\s|$)',clean),
        'exact_original_order_assertion_site':source_site==[str(MOCK_ORDER_LINE)],
        'exact_original_order_assertion_source_count':source_assert_count,
        'exact_static_departure_first_payload_count':payload_count,'assertion_payload_count':assertion_payload_count,
        'body_exit_code':code if type(code)is int else None,'separate_metadata_RED_verified':False,
        'strict_selector_PFP_credit':False,'protocol_RED':False,'raw_message_or_command_exported':False,
        'child_statuses_separately_observed':False,'both_children_zero_and_two_rows_source_implied':False}
    row['separate_metadata_RED_verified']=(type(code)is int and code==1 and row['source_test_sha_verified']
        and row['source_assertion_literal_verified'] and parent_count==subtest_count==1 and other_ok==3 and status_shape
        and summaries==['4'] and row['sole_exact_failed_subtest_header'] and not error_headers
        and row['sole_failure_summary'] and row['exact_original_order_assertion_site'] and source_assert_count==1
        and payload_count==assertion_payload_count==1 and clean.count('Traceback (most recent call last):')==1)
    # Reaching this exact assertion in the pinned source follows the unchanged
    # both-process-zero gate and its result/count/argument assertions. It is NOT
    # a separately exported child-process status observation.
    row['both_children_zero_and_two_rows_source_implied']=row['separate_metadata_RED_verified']
    row['separate_metadata_RED_counts']=({'executed':4,'passed':3,'failed':1,'errors':0,'skipped':0} if row['separate_metadata_RED_verified'] else {key:None for key in ['executed','passed','failed','errors','skipped']})
    return row

def mock_order_parser_controls():
    name=NAMES[0];description=name+' (__main__.PairingReplayDispatchTests.'+name+')'
    subtest=description+" (scope='"+MOCK_ORDER_SCOPE+"')"
    body=description+' ... \n  '+subtest+' ... FAIL\n'+''.join(other+' (__main__.PairingReplayDispatchTests.'+other+') ... ok\n' for other in NAMES[1:])
    trace='\nFAIL: '+subtest+'\nTraceback (most recent call last):\n  File "/public/scripts/test_pairing_replay_dispatch.py", line 151, in '+name+'\n    '+MOCK_ORDER_ASSERTION+"\nAssertionError: 'renewal' not found in '"+MOCK_ORDER_DEPARTURE+"'\n\nRan 4 tests in 0.123s\n\nFAILED (failures=1)\n"
    raw=body+trace
    def check(text,code=1,sha=MOCK_ORDER_SOURCE_SHA,site=True):return mock_order_diagnostic(text,code,sha,site)['separate_metadata_RED_verified']
    ensure(check(raw) and check(raw.replace('  '+subtest+' ... FAIL',subtest+' ... FAIL')),'closed-mock-subtest-known-verbose-forms')
    negative=[raw.replace("scope='pairing-departure-staggered'","scope='PRIVATE'"),raw.replace('line 151','line 152'),
        raw.replace(MOCK_ORDER_ASSERTION,'self.assertTrue(False)'),raw.replace(MOCK_ORDER_DEPARTURE,'PRIVATE'),
        raw.replace('Ran 4 tests','Ran 3 tests'),raw.replace('failures=1','failures=2'),raw+'ERROR: PRIVATE\n',
        raw.replace(' ... ok',' ... skipped reason',1),raw.replace(' ... FAIL',' ... ERROR'),raw+trace,
        raw.replace('  '+subtest+' ... FAIL\n',''),raw.replace(description+' ... \n',''),
        raw.replace(NAMES[1]+' (__main__.PairingReplayDispatchTests.'+NAMES[1]+') ... ok\n',''),
        raw.replace("AssertionError: 'renewal' not found in '","AssertionError: 'setup98' not found in '"),
        raw.replace('  '+subtest+' ... FAIL','   '+subtest+' ... FAIL'),raw.replace(name,'test_foreign')]
    for text in negative:
        row=mock_order_diagnostic(text,1,MOCK_ORDER_SOURCE_SHA,True)
        ensure(not row['separate_metadata_RED_verified'] and 'PRIVATE' not in json.dumps(row),'closed-mock-subtest-unknown-or-wrong-failure-rejected')
    ensure(not check(raw,0) and not check(raw,98) and not check(raw,True) and not check(raw,sha='0'*64) and not check(raw,site=False),'closed-mock-subtest-exit-and-source-required')
    ensure(mock_order_diagnostic(raw,1,MOCK_ORDER_SOURCE_SHA,True)['strict_selector_PFP_credit']is False,'closed-mock-regression-never-selector-PFP-credit')
    return {'positive':2,'negative':len(negative)+5,'actual_target_processes':0,'strict_selector_parser_unchanged':True,'metadata_only':True}

def parser_controls():
    prefix=''.join(name+' (__main__.PairingReplayDispatchTests.'+name+') ... '+('FAIL' if name==TARGET else 'ok')+'\n' for name in NAMES)
    bad=prefix+'\nFAIL: '+TARGET+' (__main__.PairingReplayDispatchTests.'+TARGET+')\nTraceback (most recent call last):\n  File "/public/scripts/test_pairing_replay_dispatch.py", line '+str(assertion_line())+', in '+TARGET+'\n    '+ASSERTION+'\nAssertionError: False is not true\n\nRan 4 tests in 1.234s\n\nFAILED (failures=1)\n'
    good=''.join(name+' (__main__.PairingReplayDispatchTests.'+name+') ... ok\n' for name in NAMES)+'\nRan 4 tests in 1.234s\n\nOK\n'
    ensure(green(parse(good,0)) and intended(parse(bad,1)),'closed-unittest-positive-controls')
    negatives=[bad.replace('line '+str(assertion_line()),'line '+str(assertion_line()+1)),bad.replace(ASSERTION,'self.assertTrue(False)'),
        bad.replace('False is not true','private payload'),bad.replace(' ... FAIL',' ... ERROR'),bad.replace('Ran 4 tests','Ran 0 tests'),
        bad+bad,bad.replace(TARGET,'test_foreign'),bad.replace(' ... ok',' ... skipped reason',1),bad.replace('failures=1','failures=2')]
    fourth=NAMES[3]+' (__main__.PairingReplayDispatchTests.'+NAMES[3]+') ... ok\n'
    negatives += [bad.replace(fourth,'').replace('Ran 4 tests','Ran 3 tests'),bad+fourth,
        bad.replace(fourth,fourth.replace(' ... ok',' ... FAIL')).replace('failures=1','failures=2')]
    for raw in negatives:ensure(not intended(parse(raw,1)),'unittest-adversary-rejected')
    ensure(not intended(parse(bad,0)) and not green(parse(good,1)),'exact-exit-controls')
    ensure(not green(parse(good+'FAIL: '+TARGET+' (__main__.PairingReplayDispatchTests.'+TARGET+')\n',0)),'foreign-failure-header-never-GREEN')
    repo={'full_name':'dyKiU/mdk'};head='1'*40;merge='2'*40
    event={'repository':repo,'pull_request':{'head':{'sha':head,'repo':repo},'base':{'repo':repo}}}
    ensure(event_identity('pull_request','dyKiU/mdk',event,head,merge)['event_SHA_equals_checkout'] is False,'real-PR-head-not-merge-control')
    return {'positive':3,'negative':len(negatives)+3,'mock_order_diagnostic_controls':mock_order_parser_controls(),'actual_unittest_executions':0,'compiler_or_protocol_bodies':0}

def fresh_write(path,data,mode):
    ensure(not path.is_symlink() and (not path.exists() or path.is_file()),'owned-workflow-path')
    previous=path.stat().st_mtime_ns if path.exists() else 0;path.write_bytes(data);os.chmod(path,mode)
    now=max(time.time_ns(),previous+1);os.utime(path,ns=(now,now))

def phase(label,expected,save,report):
    row={'label':label,'verified':False};report['phases'].append(row);save()
    try:
        ensure(freeze()==expected,'before-unittest-whole-source-pristine')
        code,raw,seconds=bounded.capture([sys.executable,TEST,'-v'],120,limit=256*1024)
        source_lines=Path(TEST).read_text().splitlines()
        source_at_site=len(source_lines)>=MOCK_ORDER_LINE and source_lines[MOCK_ORDER_LINE-1].strip()==MOCK_ORDER_ASSERTION
        row['mock_order_diagnostic']=mock_order_diagnostic(raw,code,digest(Path(TEST).read_bytes()),source_at_site);save()
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
        ensure(isinstance(TEST_SHA,str) and re.fullmatch('[0-9a-f]{64}',TEST_SHA) and digest(Path(TEST).read_bytes())==TEST_SHA,'frozen-unchanged-four-unit-fixture')
        report['parser_controls']=parser_controls();before=freeze();original=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
        changed=mutant(original.decode()).encode();report['source_before_sha256']=identity(before);save()
        baseline=phase('baseline',before,save,report);ensure(baseline['verified'],'fresh-four-metadata-controls-before-mutation')
        try:
            fresh_write(path,changed,mode);expected=freeze()
            ensure(set(expected)==set(before) and {p for p in before if before[p]!=expected[p]}=={WORKFLOW},'only-owned-preflight-list-changed')
            mutation=phase('mutant',expected,save,report)
        finally:
            if path.is_symlink():path.unlink()
            fresh_write(path,original,mode);restored=phase('restored',before,save,report)
        report.update(totals(report['phases']))
        report['selector_PFP_verified']=(all(p['verified'] for p in [baseline,mutation,restored])
            and all(type(report.get(k)) is int and report[k]==v for k,v in {'actual_passed':11,'actual_failed':1,'actual_errors':0,'actual_skipped':0,'actual_executed':12}.items()))
        ensure(report['selector_PFP_verified'],'exact-twelve-unit-PFP-required')
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
