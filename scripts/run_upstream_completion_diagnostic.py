#!/usr/bin/env python3
"""One unchanged ordinary case; bounded failure observations, never qualification."""
import json
import re
import subprocess
import time
from pathlib import Path
from upstream_completion_ci import ORIGINALS, compile_cases, environment, ensure, freeze, identity, parse_body

COLUMNS = ['generation','kind_0_request_1_consent_2_proof','scheduled_ms','inner_ok_ms','inner_err_ms','queued_success_observed_ms','signal_executed_ms','fresh_harvest_ms','fresh_guard_deferred_ms','periodic_owned_error_or_closed_consumed_ms','task_finished_observed_ms','last_pending_visit_ms','last_visit_periodic','owned_error_or_closed_deferred_ms']
ENUMS = {'Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite','BeforeCoreWrap','AfterCoreWrap','BeforeRelayPublication','AfterRelayPublication','VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete'}

def rust_value(raw):
    ensure(len(raw) <= 8192, 'aggregate-too-large')
    tokens = re.findall(r'Some|None|true|false|[A-Za-z_]+|[0-9]+|[\[\](),]', raw)
    ensure(''.join(tokens) == re.sub(r'\s+', '', raw), 'aggregate-unrecognized-byte')
    index = 0
    def read(depth=0):
        nonlocal index
        ensure(depth <= 16 and index < len(tokens), 'aggregate-depth-or-eof')
        token = tokens[index]; index += 1
        if token == 'Some':
            ensure(tokens[index] == '(', 'some-open'); index += 1
            value = read(depth + 1)
            ensure(tokens[index] == ')', 'some-close'); index += 1
            return value
        if token in ['[', '(']:
            close = ']' if token == '[' else ')'; values = []
            while tokens[index] != close:
                values.append(read(depth + 1)); ensure(len(values) <= 128, 'aggregate-width')
                if tokens[index] == ',': index += 1
                else: ensure(tokens[index] == close, 'aggregate-separator')
            index += 1
            return values
        if token == 'None': return None
        if token in ['true','false']: return token == 'true'
        if token.isdigit():
            value = int(token); ensure(value < 2**63, 'aggregate-integer'); return value
        ensure(token in ENUMS, 'aggregate-enum')
        return token
    value = read(); ensure(index == len(tokens), 'aggregate-trailing')
    return value

def probe_value(raw):
    value = json.loads(raw)
    ensure(set(value) == {'rows','scheduled','overflow','passes','at_ms'}, 'probe-schema')
    def integers(row, width):
        return isinstance(row,list) and len(row)==width and all(type(item) is int and 0 <= item < 2**63 for item in row)
    ensure(type(value['at_ms']) is int and 0 <= value['at_ms'] < 2**63 and type(value['overflow']) is int and 0 <= value['overflow'] < 2**63,'probe-scalars')
    ensure(type(value['scheduled']) is int and 0<=value['scheduled']<2**63,'probe-scheduled')
    ensure(isinstance(value['rows'],list) and len(value['rows'])<=32 and all(integers(row,14) for row in value['rows']),'probe-rows')
    ensure(isinstance(value['passes'],list) and len(value['passes'])==2 and all(integers(row,4) for row in value['passes']),'probe-passes')
    ensure(all(row[1] <= 2 and row[12] <= 1 for row in value['rows']),'probe-enums')
    ensure([row[0] for row in value['rows']]==list(range(1,len(value['rows'])+1)),'probe-generations')
    ensure(len(value['rows'])==min(value['scheduled'],32) and value['overflow']==max(value['scheduled']-32,0),'probe-missing-row-or-overflow')
    for row in value['rows']:
        ensure(0 < row[2] <= value['at_ms'],'probe-schedule-time')
        ensure(all(stamp==0 or row[2] <= stamp <= value['at_ms'] for index,stamp in enumerate(row) if index in [3,4,5,6,7,8,9,10,11,13]),'probe-event-time')
        ensure(row[11] or row[12]==0,'probe-visit-source-without-visit')
    for entries,tails,stamp,mask in value['passes']:
        ensure(tails<=entries and mask<512,'probe-pass-count-or-mask')
        ensure((entries==0 and tails==0 and stamp==0 and mask==0) or (entries>0 and 0<stamp<=value['at_ms']),'probe-pass-time')
    return value

def observations(raw):
    raw = re.sub(r'\x1b\[[0-9;]*m','',raw)
    result = {'sides':{},'existing':{},'parse_rejections':0,'collection_confident':True,'records':[],'probe_dump_sequence':[]}
    pending = []
    def put(target,key,value,role):
        if len(result['records'])<64: result['records'].append({'role':role,'field':key,'value':value})
        else: result['collection_confident']=False
        ensure(key not in target,'duplicate-observation')
        target[key]=value
    for line in raw.splitlines():
        try:
            match = re.fullmatch(r'completion-diag (child|existing)=(.*)',line)
            if match:
                probe = probe_value(match[2])
                ensure(len(pending)<128 and len(result['probe_dump_sequence'])<128,'probe-dump-limit')
                pending.append((match[1],probe))
                result['probe_dump_sequence'].append({'kind':match[1],'probe':probe})
                result['collection_confident'] &= probe_confident(probe)
                continue
            match = re.fullmatch(r'automatic-enrollment-control side=(left|right) (.*)',line)
            if match:
                side = result['sides'].setdefault(match[1],{}); text = match[2]
                parts = re.fullmatch(r'primary/expected/children/completed=(.*?) intake=(.*?) rejections=(.*?) context_rejections=(.*?) projection=(.*)',text)
                if parts:
                    for key,value in zip(['completion','intake','rejections','context_rejections','projection'],parts.groups()): put(side,key,rust_value(value),match[1])
                elif text.startswith('child_channels='):
                    ensure(all(kind=='child' for kind,_ in pending),'probe-role-mismatch')
                    put(side,'children',rust_value(text.split('=',1)[1]),match[1])
                    put(side,'publication_probes',[probe for _,probe in pending],match[1]); pending=[]
                elif text.startswith('native_rpc_counts/elapsed_ms/branch='): put(side,'native_rpc',rust_value(text.split('=',1)[1]),match[1])
                else: raise ValueError('unknown-side-observation')
                continue
            match = re.fullmatch(r'automatic-enrollment-control existing_index=([0-9]+) child_channel=(.*)',line)
            if match:
                ensure(int(match[1]) < 128,'existing-index')
                ensure(all(kind=='existing' for kind,_ in pending),'probe-role-mismatch')
                put(result['existing'],match[1],{'channel':rust_value(match[2]),'publication_probes':[probe for _,probe in pending]},'existing'); pending=[]
                continue
            if line.startswith('automatic-enrollment-control stage='):
                ensure(re.fullmatch(r'automatic-enrollment-control stage=(?:initial-two|third-device|fourth-device)-(?:comparison|completion|completed)',line) is not None,'unknown-phase-marker')
                continue
            if line.startswith(('automatic-enrollment-control','completion-diag')): raise ValueError('unknown-observation-line')
        except (ValueError,IndexError,TypeError,json.JSONDecodeError):
            result['parse_rejections'] += 1; result['collection_confident']=False
    result['unattributed_probe_count']=len(pending)
    if pending: result['collection_confident']=False
    markers=re.findall(r'automatic-enrollment-control stage=((?:third|fourth)-device-complet(?:ion|ed))',raw)
    result['fourth_timeout_window_identified']=markers==['third-device-completion','third-device-completed','fourth-device-completion']
    try: result['inventory_complete']=inventory_complete(result)
    except (ValueError,IndexError,TypeError):
        result['inventory_complete']=False; result['parse_rejections']+=1
    result['collection_confident'] &= result['fourth_timeout_window_identified'] and result['inventory_complete']
    return result

def inventory_complete(result):
    def numbers(value,count): return isinstance(value,list) and len(value)==count and all(type(item) is int and 0<=item<2**63 for item in value)
    def channel(value):
        return isinstance(value,list) and len(value)==5 and numbers(value[:3],3) and value[0]<256 and (value[3] is None or value[3] in {'Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite'}) and (value[4] is None or value[4] in {'BeforeCoreWrap','AfterCoreWrap','BeforeRelayPublication','AfterRelayPublication'})
    fields={'completion','intake','rejections','context_rejections','projection','children','native_rpc','publication_probes'}
    if set(result['sides'])!={'left','right'} or set(result['existing'])!={'0','1'}: return False
    for name,side in result['sides'].items():
        if set(side)!=fields: return False
        children=side['children']; count=0 if children is None else len(children) if isinstance(children,list) else -1
        if count<0 or len(side['publication_probes'])!=count: return False
        if children is not None and any(not channel(child) for child in children): return False
        completion=side['completion']
        if completion is None:
            if name!='left' or count!=0: return False
        elif not isinstance(completion,list) or len(completion)!=4 or type(completion[0]) is not bool or any(type(value) is not int for value in completion[1:]) or completion[2]!=count or not 0<=completion[3]<=count: return False
        if name=='right' and (count!=2 or completion[1]!=2): return False
        if name=='left' and count!=0: return False
        for field,width in [('intake',8),('rejections',4),('context_rejections',9),('projection',4)]:
            if not (side[field] is None and completion is None) and not numbers(side[field],width): return False
        rpc=side['native_rpc']
        if rpc is None:
            if completion is not None: return False
        elif not isinstance(rpc,list) or len(rpc)!=3 or not numbers(rpc[0],6) or not numbers(rpc[1],6) or not (rpc[2] is None or isinstance(rpc[2],list) and len(rpc[2])==2 and rpc[2][0] in {'VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete'} and type(rpc[2][1]) is int): return False
    return all(channel(value['channel']) and len(value['publication_probes'])==1 for value in result['existing'].values()) and len(result['probe_dump_sequence'])==4

def probe_confident(probe):
    if probe['overflow']: return False
    for row in probe['rows']:
        if (row[7] or row[11]) and not any(passes[0] for passes in probe['passes']): return False
        if row[3] and row[4]: return False
        if row[5] and not (row[3] and row[2] <= row[3] <= row[5]): return False
        if row[6] and not (row[5] and row[5] <= row[6]): return False
        # Queue observation can race harvest observation on another thread;
        # actual successful queue is required, their timestamp order is not.
        if row[7] and not (row[3] and row[5] and row[3] <= row[7]): return False
        if row[7] and (not row[11] or row[11]>row[7] or row[10]>row[7]): return False
        if row[7] and (row[9] or row[13]): return False
        if row[8] and not (row[3] and row[3]<=row[8] and (not row[7] or row[8]<=row[7])): return False
        if row[4] and (row[5] or row[6] or row[7] or row[8]): return False
        if row[10] and any(stamp and stamp>row[10] for stamp in [row[3],row[4],row[5],row[6]]): return False
        for column in [9,13]:
            if row[column] and any(stamp and stamp>row[column] for stamp in [row[3],row[4]]): return False
        if row[9] and row[13] and row[13]>row[9]: return False
    return True

def parser_preflight():
    ensure(rust_value('Some((true, Some(2), 2, 0))')==[True,2,2,0],'rust-parser-positive')
    row=[1,1,1,2,0,3,4,5,0,0,0,4,1,0]
    probe={'rows':[row],'scheduled':1,'overflow':0,'passes':[[1,1,6,31],[0]*4],'at_ms':7}
    ensure(probe_value(json.dumps(probe))==probe,'probe-parser-positive')
    ensure(probe_confident(probe),'harvest-does-not-require-task-finished-observation')
    rejected=0
    for bad in ['Some(account_identifier)','Some("payload")','[1, -1]','[1, 2] trailing']:
        try: rust_value(bad)
        except (ValueError,IndexError): rejected+=1
    ensure(rejected==4,'rust-parser-negatives')
    overflow=dict(probe,overflow=1)
    ensure(not probe_confident(overflow),'overflow-not-confident')
    for column in [3,5]:
        changed=list(row); changed[column]=0
        ensure(not probe_confident(dict(probe,rows=[changed])),'harvest-missing-inner-success-or-queue')
    positives=3; negatives=7
    late=list(row); late[5]=6; late[6]=7
    ensure(probe_confident(dict(probe,rows=[late],at_ms=8)),'queue-observation-may-follow-harvest'); positives+=1
    channel='(31, 2, 0, None, Some(AfterRelayPublication))'
    z=lambda n: '['+', '.join(['0']*n)+']'
    dump='completion-diag child='+json.dumps(probe)
    existing='completion-diag existing='+json.dumps(probe)
    lines=[
        'automatic-enrollment-control stage=third-device-completion',
        'automatic-enrollment-control stage=third-device-completed',
        'automatic-enrollment-control stage=fourth-device-completion',
        'automatic-enrollment-control side=left primary/expected/children/completed=None intake=None rejections=None context_rejections=None projection=None',
        'automatic-enrollment-control side=left child_channels=None',
        'automatic-enrollment-control side=left native_rpc_counts/elapsed_ms/branch=None',
        'automatic-enrollment-control side=right primary/expected/children/completed=Some((true, Some(2), 2, 0)) intake=Some('+z(8)+') rejections=Some('+z(4)+') context_rejections=Some('+z(9)+') projection=Some('+z(4)+')',
        dump,dump,
        'automatic-enrollment-control side=right child_channels=Some(['+channel+', '+channel+'])',
        'automatic-enrollment-control side=right native_rpc_counts/elapsed_ms/branch=Some(('+z(6)+', '+z(6)+', Some((SharingPending, 1))))',
        existing,'automatic-enrollment-control existing_index=0 child_channel=Some('+channel+')',
        existing,'automatic-enrollment-control existing_index=1 child_channel=Some('+channel+')',
    ]
    full='\n'.join(lines); ensure(observations(full)['collection_confident'],'complete-fourth-inventory'); positives+=1
    variants=[
        '', '\n'.join(lines[:-2]), full+'\n'+lines[5], full+'\n'+lines[-1],
        full.replace(dump+'\n'+dump,dump,1), full+'\nautomatic-enrollment-control unknown=1',
        full.replace('stage=fourth-device-completion','stage=third-device-completion'),
        full.replace('existing_index=1','existing_index=0'),
    ]
    for sample in variants:
        ensure(not observations(sample)['collection_confident'],'missing-duplicate-or-unknown-inventory'); negatives+=1
    malformed=[]
    malformed.append(dict(probe,rows=[row,row],scheduled=2))
    zero=list(row); zero[0]=0; malformed.append(dict(probe,rows=[zero]))
    future=list(row); future[5]=8; malformed.append(dict(probe,rows=[future]))
    early=list(row); early[2]=3; malformed.append(dict(probe,rows=[early]))
    malformed.extend([dict(probe,scheduled=2),dict(probe,passes=[[1,1,6,512],[0]*4]),dict(probe,passes=[[0,1,6,31],[0]*4])])
    for sample in malformed:
        rejected=False
        try: probe_value(json.dumps(sample))
        except (ValueError,TypeError,IndexError): rejected=True
        ensure(rejected,'probe-structural-or-time-negative'); negatives+=1
    for column in [8,10,6]:
        impossible=list(row); impossible[column]=1
        ensure(not probe_confident(dict(probe,rows=[impossible])),'probe-impossible-event-order'); negatives+=1
    return {'positive_controls':positives,'negative_controls':negatives,'actual_product_bodies':0}

def main():
    out=Path('completion-diagnostic-evidence'); out.mkdir(exist_ok=True)
    report=environment(); report.update(qualification_passed=False,scope='one unchanged ordinary enrollment case; passive instrumentation overhead; no mutation qualification',columns=COLUMNS,pass_schema={'rows':['periodic','wake'],'columns':['entries','tails','last_observed_ms','last_observed_mask'],'mask_bits':['cheap_state_live','ready','handshake_published','policy_committed','proof_published','peer_committed','complete','publication_present','deferred_initial_error_present'],'mask_semantics':'Cached scheduling flags and cheap State.live only. No fresh original/context/guard validation; unlike original periodic-only channel_bits.'},time_schema='Per-State relative milliseconds plus one; zero means unknown. Never compare clocks across probes. queued_success is observed successful send; failed/closed queue status can remain unknown. signal_executed is sender invocation, not receiver observation; wake pass entry is recorded separately.')
    report['collection_limits']='Cached snapshots are read sequentially AFTER the timeout verdict; workers may advance during collection. States are not simultaneous, and per-State ages are relative to each snapshot, not the deadline or phase start. A post-timeout successful task does not alone establish completion before the deadline.'
    report['probe_schema']={'scheduled':'All per-State scheduling observations','rows':'First min(scheduled,32) contiguous local generations','overflow':'scheduled minus retained rows; nonzero invalidates collection confidence','at_ms':'Per-State snapshot age, not a shared clock'}
    def save(): (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    frozen=freeze(); report['source_before_sha256']=identity(frozen); save()
    try:
        compilation,cases=compile_cases([ORIGINALS[0]]); report['compilation']=compilation; save()
        ensure(freeze()==frozen,'compile-input-drift')
        ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') and len(cases)==1,'compile-or-inventory-not-qualified')
        case=cases[ORIGINALS[0]]; start=time.monotonic(); row={'test':case['name'],'binary_sha256':case['binary_sha256']}
        try:
            body=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
            raw=body.stdout+body.stderr; row.update(body_exit_code=body.returncode)
        except subprocess.TimeoutExpired as error:
            def text(value): return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
            raw=text(error.stdout)+text(error.stderr); row.update(watchdog_triggered=True,actual_count_unknown=True)
        row.update(body_seconds=time.monotonic()-start,**parse_body(raw,ORIGINALS[0])); row['observations']=observations(raw)
        row['failure_observations_available']=bool(row['observations']['sides'] or row['observations']['existing'])
        if row.get('watchdog_triggered'): row['actual_count_unknown']=True
        report['body']=row; report['diagnostic_collection_complete']=row.get('executed_nonignored')==1 and row.get('ignored')==0 and not row.get('watchdog_triggered') and row['observations']['collection_confident']
    except Exception as error: report['controller_exception']=type(error).__name__
    finally:
        report['inputs_pristine']=freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
        report['source_after_sha256']=identity(freeze()); save()
    row=report.get('body',{})
    raise SystemExit(0 if row.get('body_exit_code')==0 and row.get('passed')==1 and report.get('diagnostic_collection_complete') and report['inputs_pristine'] else 1)
if __name__=='__main__': main()
