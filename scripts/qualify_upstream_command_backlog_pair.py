#!/usr/bin/env python3
"""Fresh refactored behavioral RED and genuine pending-input command control; no qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_command_backlog_red as red

BASE = 'c3939a775d81f6d9380a9318ca9f729a774ef990'
HISTORICAL_METADATA = 'a445951853e2383bcbc4bf3af29d23fa1b30e889'
SELF = 'scripts/qualify_upstream_command_backlog_pair.py'
MANIFEST = 'scripts/command_backlog_pair_source_manifest.json'
MANIFEST_SHA = '581b9cda77f8a92152581b1ce04a37ddd43093e774a24b2fc74f782083ee1bef'  # Root pins only the final independently reviewed/formatted source manifest.
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-private-command-backlog-red-20261018'
BEGIN = '  # COMMAND_BACKLOG_PAIR_JOBS_BEGIN\n'
END = '  # COMMAND_BACKLOG_PAIR_JOBS_END\n'
OPTIONS = 'options: [command-backlog-pair-preflight, command-backlog-pair-red, '
OUT = Path('command-backlog-pair-evidence')
COUNTER_CASE = 'eight_history_reads_complete_while_actual_peer_proof_is_held'
COUNTER_NAME = 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::' + COUNTER_CASE
COUNTER_FIELDS = ['actual_consent_held','initial_request_ack','exact_peer_proof_held','live_ready_pause',
    'actual_first_message_id','eight_commands_installed','authenticated_exact_body_after_reads',
    'eight_replies_before_proof_release','normal_enrollment','public_cancelled','probe_known']
ensure = red.ensure


def git_bytes(ref,path): return subprocess.check_output(['git','show',ref+':'+path])

def strip_overlay(data,begin,end,options):
    text=data.decode(); ensure(text.count(begin)==text.count(end)==text.count(options)==1,'one-owned-workflow-overlay')
    before,rest=text.split(begin); _,after=rest.split(end)
    return (before+after).replace(options,'options: [',1).encode()


def source_guard():
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(isinstance(MANIFEST_SHA,str) and re.fullmatch('[0-9a-f]{64}',MANIFEST_SHA),'final-manifest-pin-required')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('COMMAND_BACKLOG_PAIR_BASELINE')==BASE,'exact-hosted-source')
    ensure(os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('CARGO_INCREMENTAL')=='1'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
            'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-build-cohort')
    for ancestor in [BASE,HISTORICAL_METADATA]:subprocess.run(['git','merge-base','--is-ancestor',ancestor,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-pristine')
    ensure(red.digest(Path(MANIFEST).read_bytes())==MANIFEST_SHA,'final-reviewed-manifest')
    manifest=json.loads(Path(MANIFEST).read_text());ensure(manifest['baseline']==BASE and manifest['baseline_is_diagnostic_overlay'] is True,'honest-overlay-source')
    baseline={}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            meta,name=item.split(b'\t',1);mode,kind,blob=meta.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-tree')
            baseline[os.fsdecode(name)]=(mode,blob)
    historical={red.SELF,red.MANIFEST}
    additions={SELF,MANIFEST}|historical|set(manifest['new_files'])
    current=red.layout();ensure(not additions.intersection(baseline) and set(current)==set(baseline)|additions,'whole-inventory')
    for name,meta in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(meta['git_mode']==mode and meta['symlink']==(mode=='120000')
            and (meta['symlink'] or meta['actual_executable']==(mode=='100755')),'whole-source-modes')
        data=os.fsencode(os.readlink(name)) if meta['symlink'] else Path(name).read_bytes()
        if name in historical:ensure(data==git_bytes(HISTORICAL_METADATA,name),'historical-controller-and-manifest-byte-exact')
        if name in manifest['changes']:
            change=manifest['changes'][name];ensure(red.digest(data)==change['after_sha256'] and mode==change['git_mode'],'full-hook-hash')
            text=data.decode()
            for edit in reversed(change['edits']):
                ensure(text.count(edit['after'])==1,'unique-reversal');text=text.replace(edit['after'],edit['before'],1)
            data=text.encode();ensure(red.digest(data)==change['before_sha256'],'exact-hook-reconstruction')
        if name in manifest['new_files']:ensure(red.digest(data)==manifest['new_files'][name]['sha256'],'exact-new-probe-and-two-case-fixture')
        if name==WORKFLOW:
            data=strip_overlay(data,BEGIN,END,OPTIONS)
            ensure(data==git_bytes(HISTORICAL_METADATA,WORKFLOW),'historical-workflow-overlay-exact')
            data=strip_overlay(data,red.BEGIN,red.END,red.OPTIONS)
        if blob is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'entire-c393-source-reconstructed:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<={str(OUT/'result.json')},'no-extra-overlays')
    return {'baseline':BASE,'source':head,'baseline_is_diagnostic_overlay':True,'whole_c393_contents_modes_reconstructed':True,
        'historical_controller_byte_exact':True,'historical_evidence_reused':False,'pure_product_qualification':False}


def parse_counter(raw,code):
    ensure(len(raw.encode())<=8*1024*1024,'bounded-runtime-output')
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    names=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.',clean)
    clean=re.sub(r'(?m)^test '+re.escape(COUNTER_NAME)+r' \.\.\. (?=command-backlog-progress )','',clean)
    row=dict(red.parse_body(clean,COUNTER_CASE),body_exit_code=code,executed_case_names=names,
        compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',clean,re.M)),
        running_counts=[int(v) for v in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$',clean)])
    lines=[line for line in clean.splitlines() if line.startswith('command-backlog')]
    row['marker_header_count']=len(lines)
    pattern=r'command-backlog-progress facts=\['+', '.join([r'(true|false)']*11)+r'\] completed_before=(None|Some\([0-8]\))'
    pattern+=r' runtime_closes=([0-3]) plane_shutdown_returns=([0-3]) relay_closed=(true|false) attempt_completed=(true|false)'
    ensure(len(lines)==1 and len(lines[0])<1024,'one-counterpart-marker')
    found=re.fullmatch(pattern,lines[0]);ensure(found is not None,'closed-counterpart-facts')
    values=found.groups();row['facts']=dict(zip(COUNTER_FIELDS,[v=='true' for v in values[:11]]))
    row.update(completed_before=None if values[11]=='None' else int(values[11][5:-1]),runtime_closes=int(values[12]),
        plane_shutdown_returns=int(values[13]),relay_closed=values[14]=='true',attempt_completed=values[15]=='true')
    return row


def counter_green(row):
    return (all(type(row.get(k)) is int and row[k]==v for k,v in {'body_exit_code':0,'passed':1,'failed':0,'ignored':0,
        'executed_nonignored':1,'compiler_error_count':0,'all_panic_header_count':0,'marker_header_count':1,
        'completed_before':8,'runtime_closes':3,'plane_shutdown_returns':3}.items())
        and row.get('running_counts')==[1] and row.get('executed_case_names')==[COUNTER_NAME]
        and all(row.get('facts',{}).get(k) is True for k in COUNTER_FIELDS)
        and row.get('relay_closed') is True and row.get('attempt_completed') is True
        and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


U64_MAX=18446744073709551615
QU=r'(?:0|[1-9][0-9]{0,19})'
QD=r'(?:None|Some\(\('+QU+r', '+QU+r'\)\))'
QR=r'(?:None|Some\(\(\['+QU+r'(?:, '+QU+r'){7}\], \['+QU+r'(?:, '+QU+r'){5}\], '+QD+r', '+QU+r', (?:true|false), (?:true|false)\)\))'


def queue_row(text):
    if text=='None':return None
    match=re.fullmatch(r'Some\(\(\[('+QU+r'(?:, '+QU+r'){7})\], \[('+QU+r'(?:, '+QU+r'){5})\], ('+QD+r'), ('+QU+r'), (true|false), (true|false)\)\)',text)
    ensure(match is not None,'closed-queue-row')
    counts=[int(v) for v in match[1].split(', ')];placements=[int(v) for v in match[2].split(', ')];dequeued=int(match[4])
    ensure(all(v<=U64_MAX for v in counts+placements+[dequeued]),'queue-u64-bounds')
    depths=None
    if match[3]!='None':
        depth=re.fullmatch(r'Some\(\(('+QU+r'), ('+QU+r')\)\)',match[3]);before,after=int(depth[1]),int(depth[2])
        ensure(before<=1025 and after<=1025 and placements[0]>0,'queue-accepted-depth-coherence')
        depths={'before':before,'after':after}
    first=match[5]=='true';ensure(first==(dequeued>0),'queue-first-dequeue-presence-coherence')
    return {'counts':counts,'placement_counts':placements,'first_accepted_send_depths':depths,
        'successful_account_delivery_receive_count':dequeued,'first_dequeue_observed':first,
        'invalid_observation':match[6]=='true','dequeue_does_not_establish_Core_acceptance':True}


def extract_queue(raw):
    ensure(len(raw.encode())<=8*1024*1024,'queue-bounded-input')
    clean=re.sub(r'\x1b\[[0-9;]*m','',raw)
    lines=[line for line in clean.splitlines() if line.startswith('command-backlog-queue')]
    ensure(len(lines)==1 and len(lines[0].encode())<4096,'one-bounded-queue-marker')
    line=lines[0]
    pattern=r'command-backlog-queue pause_rx_len=(None|Some\('+QU+r'\)) target=('+QR+r') own_id_bound=(None|Some\((?:true|false)\)) own=('+QR+r')'
    match=re.fullmatch(pattern,line);ensure(match is not None,'closed-queue-marker')
    pause=None if match[1]=='None' else int(match[1][5:-1]);ensure(pause is None or pause<=1025,'bounded-pause-depth')
    target,own=queue_row(match[2]),queue_row(match[4]);bound=None if match[3]=='None' else match[3]=='Some(true)'
    ensure(own is None or bound is True,'own-row-requires-real-immutable-ID-binding')
    closed={'schema_complete':True,'pause_rx_len':pause,'target':target,'own_id_bound':bound,'own':own,
        'own_missing_is_unknown_not_absence':True,'depths_and_dequeue_are_not_atomic_FIFO_evidence':True,
        'transport_counts_are_not_authority_or_final_enrollment':True}
    # Preserve every inherited fact/fullname line; remove only this validated line.
    filtered=''.join(part for part in clean.splitlines(keepends=True) if part.rstrip('\r\n')!=line)
    return filtered,closed


def queue_gate(row,is_red):
    if row.get('schema_complete') is not True or type(row.get('pause_rx_len')) is not int or row['pause_rx_len']!=0:return False
    if not is_red:return True
    target=row.get('target')
    return (isinstance(target,dict) and isinstance(target.get('placement_counts'),list) and len(target['placement_counts'])==6
        and all(type(v) is int and 0<=v<=U64_MAX for v in target['placement_counts']) and target['placement_counts'][0]>0
        and isinstance(target.get('first_accepted_send_depths'),dict)
        and all(type(target['first_accepted_send_depths'].get(k)) is int and target['first_accepted_send_depths'][k]==v for k,v in [('before',0),('after',1)])
        and type(target.get('successful_account_delivery_receive_count')) is int and target['successful_account_delivery_receive_count']==0
        and target.get('first_dequeue_observed') is False and target.get('invalid_observation') is False)


def queue_parser_controls():
    counts='[1, 1, 0, 1, 0, 1, 0, 1]';placements='[1, 0, 0, 0, 0, 0]'
    target='Some(('+counts+', '+placements+', Some((0, 1)), 0, false, false))'
    marker='command-backlog-queue pause_rx_len=Some(0) target='+target+' own_id_bound=None own=None'
    raw='running 1 test\ncommand-backlog facts=UNCHANGED\n'+marker+'\n'
    filtered,row=extract_queue(raw);ensure(queue_gate(row,True) and 'command-backlog facts=UNCHANGED' in filtered and 'command-backlog-queue' not in filtered,'queue-prerequisite-positive')
    unknown='command-backlog-queue pause_rx_len=Some(0) target=None own_id_bound=Some(false) own=None'
    ensure(queue_gate(extract_queue(unknown)[1],False) and not queue_gate(extract_queue(unknown)[1],True),'counterpart-does-not-require-unknown-self-echo')
    own=marker.replace('own_id_bound=None own=None','own_id_bound=Some(true) own='+target)
    ensure(queue_gate(extract_queue(own)[1],True),'supplemental-real-own-ID-positive')
    no_depth=marker.replace('Some((0, 1))','None')
    ensure(not queue_gate(extract_queue(no_depth)[1],True) and queue_gate(extract_queue(no_depth)[1],False),'unknown-depth-not-RED-but-counterpart-stays-independent')
    negatives=0
    for delta in [{'pause_rx_len':None},{'pause_rx_len':False},{'pause_rx_len':1},{'schema_complete':False},{'target':None}]:
        ensure(not queue_gate(dict(row,**delta),True),'missing-primary-queue-prerequisite-denied');negatives+=1
    for delta in [{'placement_counts':[True,0,0,0,0,0]},{'first_accepted_send_depths':{'before':1,'after':2}},{'first_accepted_send_depths':{'before':False,'after':True}},{'successful_account_delivery_receive_count':1},
                  {'successful_account_delivery_receive_count':False},{'first_dequeue_observed':True},{'invalid_observation':True}]:
        ensure(not queue_gate(dict(row,target=dict(row['target'],**delta)),True),'wrong-target-queue-prerequisite-denied');negatives+=1
    for bad in ['',marker+'\n'+marker,marker+' raw=PRIVATE_PAYLOAD',marker.replace('Some(0) target','Some(1026) target'),
        marker.replace('Some((0, 1))','Some((0, 1026))'),marker.replace(placements,'[0, 0, 0, 0, 0, 0]'),
        marker.replace(', 0, false, false))',', 1, false, false))'),marker.replace(', 0, false, false))',', 0, true, false))'),
        marker.replace(counts,'[18446744073709551616, 1, 0, 1, 0, 1, 0, 1]'),
        marker.replace(counts,'[true, 1, 0, 1, 0, 1, 0, 1]'),own.replace('own_id_bound=Some(true)','own_id_bound=Some(false)'),
        marker.replace('own_id_bound=None','own_id_bound=Some(PRIVATE_PAYLOAD)')]:
        try:extract_queue(bad)
        except ValueError:negatives+=1;continue
        raise ValueError('malformed-queue-observation-accepted')
    red_bits=['true']*13;red_bits[11]='false'
    red_marker='command-backlog facts=['+', '.join(red_bits)+'] completed_before=Some(8) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true'
    red_raw='running 1 test\ntest '+red.NAME+' ... FAILED\n'+red_marker+'\n'+marker+'\nthread test panicked at '+red.FIXTURE+':'+str(red.assertion_line())+':5:\n'+red.MESSAGE+'\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    filtered,queue=extract_queue(red_raw)
    ensure(red.intended_red(red.parse(filtered,101)) and queue_gate(queue,True),'integrated-original-RED-and-primary-queue-positive')
    counter_marker='command-backlog-progress facts=['+', '.join(['true']*11)+'] completed_before=Some(8) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true'
    counter_raw='running 1 test\ntest '+COUNTER_NAME+' ... ok\n'+counter_marker+'\n'+unknown+'\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    filtered,queue=extract_queue(counter_raw)
    ensure(counter_green(parse_counter(filtered,0)) and queue_gate(queue,False),'integrated-counterpart-PASS-and-unknown-supplement-positive')
    return {'positive':6,'negative':negatives,'runtime_bodies':0,'supplemental_own_ID_is_not_required_for_counterpart':True}


def parser_controls():
    inherited=red.parser_controls();queue_controls=queue_parser_controls()
    marker='command-backlog-progress facts=['+', '.join(['true']*11)+'] completed_before=Some(8) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true'
    raw='running 1 test\ntest '+COUNTER_NAME+' ... ok\n'+marker+'\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n'
    row=parse_counter(raw,0);ensure(counter_green(row),'genuine-counterpart-positive')
    ensure(counter_green(parse_counter(raw.replace(' ... ok\n'+marker,' ... '+marker),0)),'counterpart-shared-prefix-positive')
    negatives=0
    for delta in [{'body_exit_code':False},{'passed':True},{'failed':False},{'ignored':False},{'completed_before':True},
        {'completed_before':7},{'completed_before':None},{'passed':0},{'failed':1},{'ignored':1},{'executed_nonignored':0},
        {'compiler_error_count':1},{'all_panic_header_count':1},{'runtime_closes':2},{'plane_shutdown_returns':2},
        {'relay_closed':False},{'attempt_completed':False},{'running_counts':[0]},{'executed_case_names':[COUNTER_NAME,COUNTER_NAME]},
        {'watchdog_triggered':True},{'actual_count_unknown':True}]:
        ensure(not counter_green(dict(row,**delta)),'non-counterpart-rejected');negatives+=1
    for field in COUNTER_FIELDS:
        ensure(not counter_green(dict(row,facts=dict(row['facts'],**{field:False}))),'all-command-control-facts-required');negatives+=1
    for bad in [raw+'\n'+marker,raw.replace('Some(8)','Some(99)'),raw.replace(marker,marker+' raw=private')]:
        try:parse_counter(bad,0)
        except ValueError:negatives+=1;continue
        raise ValueError('malformed-counterpart-marker-accepted')
    ensure(not counter_green(parse_counter(raw.replace(COUNTER_NAME,COUNTER_NAME+'_other'),0)),'wrong-counterpart-name');negatives+=1
    return {'original_RED_controls':inherited,'queue_controls':queue_controls,'counterpart_positive':2,'counterpart_negative':negatives,'runtime_bodies':0}


def aggregates(rows):
    fields=['passed','failed','ignored','executed_nonignored']
    return {'actual_'+key:sum(row[key] for row in rows) if len(rows)==2 and all(type(row.get(key)) is int for row in rows) else None for key in fields} | {
        'known_partial_counts':{key:sum(row[key] for row in rows if type(row.get(key)) is int) for key in fields},
        'unknown_count_cases':2-sum(all(type(row.get(key)) is int for key in fields) for row in rows)}


def main(options):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'qualification_passed':False,'default_qualified':False,'native_qualified':False,'mutation_claim':False,
        'paired_red_control_verified':False,'refactored_behavioral_red_verified':False,'command_progress_control_passed':False,'cases':[]}
    report.update(aggregates([]));report['expected_executed_bodies']=2
    before=modes=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if options.preflight:report['preflight_passed']=True;save();return
        report['environment']=red.environment();before,modes=red.freeze(),red.layout()
        compilation,cases=red.compile_cases([red.CASE,COUNTER_CASE])
        headers=compilation.pop('compiler_headers',[])
        compilation['compiler_codes']=sorted(set(re.findall(r'error\[(E[0-9]{4})\]','\n'.join(headers))))
        compilation['compiler_sites']=[{'file':p,'line':int(n),'column':int(c)} for p,n,c in re.findall(r'--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)','\n'.join(headers))]
        report['compilation']=compilation;save()
        ensure(compilation.get('compile_exit_code')==compilation.get('compiler_error_count')==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)=={red.CASE,COUNTER_CASE}
            and cases[red.CASE]['name']==red.NAME and cases[COUNTER_CASE]['name']==COUNTER_NAME
            and cases[red.CASE]['binary_sha256']==cases[COUNTER_CASE]['binary_sha256'],'two-actual-cases-same-feature-verified-binary')
        report['feature_identity']=red.feature_identity(compilation);binary=cases[red.CASE]['binary'];binary_sha=cases[red.CASE]['binary_sha256']
        report['binary_sha256']=binary_sha
        for suffix,name,parser,gate in [(red.CASE,red.NAME,red.parse,red.intended_red),(COUNTER_CASE,COUNTER_NAME,parse_counter,counter_green)]:
            phase={'name':name,'runtime_started':False};report['cases'].append(phase)
            try:
                ensure(red.freeze()==before and red.layout()==modes and red.digest(Path(binary).read_bytes())==binary_sha,'before-each-case-pristine')
                phase['runtime_started']=True;save()
                code,raw,seconds=red.bounded.capture([binary,'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
                phase['body']=dict(red.parse_body(raw,suffix),body_exit_code=code,seconds=seconds,
                    compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)));save()
                phase['post_body_binary_sha256']=red.digest(Path(binary).read_bytes())
                phase['post_body_binary_pristine']=phase['post_body_binary_sha256']==binary_sha;save()
                ensure(phase['post_body_binary_pristine'],'actual-post-body-binary-pristine')
                phase['queue_schema_complete']=False;save()
                filtered,phase['queue_observation']=extract_queue(raw);phase['queue_schema_complete']=True;save()
                phase['body']=dict(parser(filtered,code),seconds=seconds)
                phase['queue_prerequisite_verified']=queue_gate(phase['queue_observation'],suffix==red.CASE)
                phase['expected_outcome_verified']=gate(phase['body']) and phase['queue_prerequisite_verified']
            except red.bounded.GateFailure as error:
                phase['watchdog_triggered']=str(error)=='bounded-command-timeout';phase['output_limit_triggered']=str(error)=='bounded-command-output-limit'
                phase['actual_count_unknown']=True;phase['exception_type']=type(error).__name__
            except Exception as error:phase['exception_type']=type(error).__name__
            finally:
                phase['final_binary_sha256']=red.digest(Path(binary).read_bytes())
                phase['inputs_pristine']=red.freeze()==before and red.layout()==modes and red.digest(Path(binary).read_bytes())==binary_sha
                if not phase['inputs_pristine']:phase['expected_outcome_verified']=False
                report.update(aggregates([p.get('body',{}) for p in report['cases']]));save()
        report['refactored_behavioral_red_verified']=report['cases'][0].get('expected_outcome_verified') is True
        report['command_progress_control_passed']=report['cases'][1].get('expected_outcome_verified') is True
        report['paired_red_control_verified']=report['refactored_behavioral_red_verified'] and report['command_progress_control_passed']
        save();ensure(report['paired_red_control_verified'],'fresh-refactored-RED-plus-command-progress-PASS-required')
    except Exception as error:report['exception_type']=type(error).__name__;raise
    finally:
        if before is not None:
            report['inputs_pristine']=red.freeze()==before and red.layout()==modes
            if not report['inputs_pristine']:
                for flag in ['paired_red_control_verified','refactored_behavioral_red_verified','command_progress_control_passed']:report[flag]=False
        save()
        if before is not None:ensure(report['inputs_pristine'],'finally-source-modes-pristine')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--preflight',action='store_true');main(parser.parse_args())
