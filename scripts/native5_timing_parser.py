"""Closed fixed-slot passive data; never raw identifiers, payloads or errors."""
import re
MILESTONES=['prepared','validated','task_poll','adapter_callsite','adapter_returned','accepted_ack','result_send','result_receive','harvest_success']
OUTCOMES=['adapter_result_ok','returned_report_met_required_acks','result_send_accepted','received_result_ok','harvest_accepted']
PROOF_PREPARATION=['seal_before','seal_after','wrap_before','wrap_after']
SPAWN_BOUNDARIES=['negative_hook_before','negative_hook_after','publication_mutex_before','publication_mutex_after','spawn_before','spawn_returned']
CHANNEL_PROGRESS=['policy_first_call','policy_commit_success','proof_eligibility','authenticated_peer_proof_accepted','actual_complete_write']
RPC_STAGES=['dispatch','worker_started','worker_returned','reply_send','facade_returned']
RPC_RESULTS=['AwaitingSetup','AwaitingPeer','ComparisonAvailable','AwaitingPeerVerification','VerificationCompleteEnrollmentPending','Cancelled','Expired','Failed','EnrollmentComplete','ResponseTimedOut','OtherError']
N=r'(?:0|[1-9][0-9]{0,9})'; ON=r'(?:None|Some\('+N+r'\))'; OB=r'(?:None|Some\((?:true|false)\))'
def require(v,k):
    if not v:raise ValueError(k)
def number(s,maximum=600000000):
    require(re.fullmatch(N,s) is not None,'closed-number');v=int(s);require(v<=maximum,'bounded-number');return v
def opt(s,maximum=600000000):
    if s=='None':return None
    require(re.fullmatch(r'Some\('+N+r'\)',s) is not None,'closed-option-number');return number(s[5:-1],maximum)
def boolean(s):
    require(s in {'None','Some(true)','Some(false)'},'closed-option-bool');return None if s=='None' else s=='Some(true)'
def relation(t,lo,hi):
    if t is None or lo is None or hi is None:return 'unknown'
    return 'definitely_before_deadline' if t<lo else 'definitely_after_deadline' if t>hi else 'ambiguous_construction_interval'
def ordered_observed(values):
    observed=[value for value in values if value is not None]
    return all(a<=b for a,b in zip(observed,observed[1:]))
def timing(raw,name):
    require(len(raw.encode())<=8*1024*1024,'bounded-output')
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    raw,prefix=re.subn(r'(?m)^test '+re.escape(name)+r' \.\.\. (?=native5-consent-)','',raw)
    require(prefix<=1 and not re.search(r'(?m)^test [A-Za-z0-9_:]+ \.\.\. native5-consent-',raw),'exact-shared-prefix')
    lines=[s for s in raw.splitlines() if s.startswith('native5-consent-')]
    if not lines:
        return {'observed':False,'known':False,'loss_mask':None,'snapshot_available':False,
            'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,
            'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,
            'missing_is_not_zero':True,'all_milestones_observed':False,'missing_reason':'NoOwnedProbeReport'}
    require(len(lines)<=140 and all(len(s)<4096 for s in lines),'bounded-lines')
    h=re.fullmatch(r'native5-consent-timing known=(true|false) loss_mask=('+N+r') snapshot_available=(true|false)',lines[0]);require(h is not None,'closed-header')
    known=h[1]=='true';loss=number(h[2],127);available=h[3]=='true'
    require(known==(loss==0) and (available or not known),'loss-unknown-semantics')
    result={'observed':True,'known':known,'loss_mask':loss,'snapshot_available':available,'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,'missing_is_not_zero':True,'all_milestones_observed':False}
    if not available:require(len(lines)==1,'no-invented-unavailable-rows');return result
    require(len(lines)>=12,'three-channel-phase-slots-and-rpc-count')
    w=re.fullmatch(r'native5-consent-wait constructed_before_us=('+ON+r') constructed_after_us=('+ON+r') deadline_lower_us=('+ON+r') deadline_upper_us=('+ON+r') outcome_ok=('+OB+r') observed_us=('+ON+r') exact_deadline_known=false',lines[1]);require(w is not None,'closed-wait')
    before,after,lo,hi=[opt(w[i],615000000) for i in range(1,5)]
    require(lo==(None if before is None else before+15000000) and hi==(None if after is None else after+15000000) and (before is None or after is None or before<=after),'original-duration-bounds')
    result['wait']={'constructed_before_us':before,'constructed_after_us':after,'deadline_lower_us':lo,'deadline_upper_us':hi,'outcome_ok':boolean(w[5]),'observed_us':opt(w[6])}
    if known:
        require(after is None or result['wait']['observed_us'] is None or after<=result['wait']['observed_us'],'wait-observation-not-before-construction')
    pattern=r'native5-consent-slot index=([012]) observation=(?:None|Some\(\(\['+', '.join(['('+ON+')']*9)+r'\], \['+', '.join(['('+OB+')']*5)+r'\], ('+N+r')\)\))'
    rows=[]
    for i,line in enumerate(lines[2:5]):
        m=re.fullmatch(pattern,line);require(m is not None and int(m[1])==i,'exact-three-slot-indices')
        if line.endswith('observation=None'):rows.append(None);continue
        times=[opt(m[j]) for j in range(2,11)];flags=[boolean(m[j]) for j in range(11,16)];retry=number(m[16],4294967295)
        if known:
            require(ordered_observed(times[:6]) and ordered_observed(times[7:9]),'owned-slot-partial-order')
            require(all(flag is None or times[event] is not None for flag,event in zip(flags,[4,4,6,7,8])),'outcome-has-actual-event')
            require(times[5] is None or flags[0] is True and flags[1] is True,'accepted-ack-has-successful-report')
        rows.append({'milestone_us':dict(zip(MILESTONES,times)),'deadline_relation':dict(zip(MILESTONES,[relation(t,lo,hi) for t in times])),'outcomes':dict(zip(OUTCOMES,flags)),'subsequent_prepared_attempts':retry})
    result['slots']=rows
    proof_pattern=r'native5-consent-proof index=([012]) observation=(?:None|Some\(\((true|false), \['+', '.join(['('+ON+')']*9)+r'\], \['+', '.join(['('+OB+')']*5)+r'\], \['+', '.join(['('+ON+')']*4)+r'\], ('+N+r'), \['+', '.join(['('+ON+')']*6)+r'\]\)\))'
    proofs=[]
    for i,line in enumerate(lines[5:8]):
        m=re.fullmatch(proof_pattern,line);require(m is not None and int(m[1])==i,'exact-three-proof-indices')
        if line.endswith('observation=None'):proofs.append(None);continue
        bound=m[2]=='true';times=[opt(m[j]) for j in range(3,12)];flags=[boolean(m[j]) for j in range(12,17)];preparation=[opt(m[j]) for j in range(17,21)];retries=number(m[21],4294967295);spawn=[opt(m[j]) for j in range(22,28)]
        if known:
            require(rows[i] is not None and preparation[0] is not None,'proof-belongs-to-observed-channel-first-seal')
            require(bound==(times[0] is not None),'actual-first-proof-message-binding')
            require(bound or all(value is None for value in times+flags),'unbound-proof-has-no-invented-publication')
            require(ordered_observed(preparation) and all(value is None or all(previous is not None for previous in preparation[:j]) for j,value in enumerate(preparation)),'proof-seal-wrap-prefix-order')
            require(times[0] is None or preparation[3] is not None and preparation[3]<=times[0],'actual-wrap-before-prepared-proof')
            require(ordered_observed(times[:6]) and ordered_observed(times[7:9]),'proof-pipeline-partial-order')
            require(all(flag is None or times[event] is not None for flag,event in zip(flags,[4,4,6,7,8])),'proof-outcome-has-actual-event')
            require(times[5] is None or flags[0] is True and flags[1] is True,'accepted-proof-ack-has-successful-report')
            require(ordered_observed(spawn) and all(value is None or all(previous is not None for previous in spawn[:j]) for j,value in enumerate(spawn)),'spawn-parent-sequential-prefix')
            require(all(value is None for value in spawn) or bound and times[1] is not None and times[1]<=next(value for value in spawn if value is not None),'spawn-after-real-validated-proof')
            require(times[2] is None or spawn[4] is not None and spawn[4]<=times[2],'task-poll-after-before-spawn-not-after-return')
        proofs.append({'first_attempt_actual_message_bound':bound,'milestone_us':dict(zip(MILESTONES,times)),
            'deadline_relation':dict(zip(MILESTONES,[relation(t,lo,hi) for t in times])),
            'outcomes':dict(zip(OUTCOMES,flags)),'preparation_us':dict(zip(PROOF_PREPARATION,preparation)),
            'preparation_deadline_relation':dict(zip(PROOF_PREPARATION,[relation(t,lo,hi) for t in preparation])),
            'spawn_boundary_us':dict(zip(SPAWN_BOUNDARIES,spawn)),'spawn_deadline_relation':dict(zip(SPAWN_BOUNDARIES,[relation(t,lo,hi) for t in spawn])),
            'spawn_return_and_task_poll_may_race':True,'subsequent_proof_attempts':retries,'later_attempt_events_are_not_merged':True})
    result['proofs']=proofs
    progress_pattern=r'native5-consent-progress index=([012]) observation=(?:None|Some\(\(\['+', '.join(['('+ON+')']*5)+r'\], \['+', '.join(['('+N+')']*5)+r'\]\)\))'
    progress=[]
    for i,line in enumerate(lines[8:11]):
        m=re.fullmatch(progress_pattern,line);require(m is not None and int(m[1])==i,'exact-three-progress-indices')
        if line.endswith('observation=None'):
            require(not known or rows[i] is None,'observed-channel-progress-snapshot-required');progress.append(None);continue
        times=[opt(m[j]) for j in range(2,7)];repeats=[number(m[j],4294967295) for j in range(7,12)]
        if known:
            require(rows[i] is not None,'progress-belongs-to-observed-channel')
            require(times[1] is None or times[0] is not None and times[0]<=times[1],'policy-success-after-first-call')
            require(proofs[i] is None or times[2] is not None,'proof-attempt-after-eligibility')
            require(times[4] is None or times[1] is not None and times[3] is not None and max(times[1],times[3])<=times[4],'actual-complete-after-policy-peer-facts')
        progress.append({'first_observed_us':dict(zip(CHANNEL_PROGRESS,times)),
            'deadline_relation':dict(zip(CHANNEL_PROGRESS,[relation(t,lo,hi) for t in times])),
            'subsequent_observation_counts':dict(zip(CHANNEL_PROGRESS,repeats)),
            'missing_peer_or_complete_is_unknown':True})
    result['channel_progress']=progress
    c=re.fullmatch(r'native5-consent-rpc-count count=('+N+r')',lines[11]);require(c is not None,'closed-rpc-count');count=number(c[1],128);require(len(lines)==12+count,'all-rpc-rows-exact')
    pattern=r'native5-consent-rpc index=('+N+r') times=\['+', '.join(['('+ON+')']*5)+r'\] results=\['+', '.join(['('+ON+')']*2)+r'\] sent=('+OB+r')'
    result['rpc']=[]
    for i,line in enumerate(lines[12:]):
        m=re.fullmatch(pattern,line);require(m is not None and number(m[1],127)==i,'unique-ordered-rpc-index')
        times=[opt(m[j]) for j in range(2,7)];categories=[opt(m[j],10) for j in (7,8)]
        if known:
            require(ordered_observed(times[:4]) and ordered_observed([times[0],times[4]]),'same-operation-rpc-partial-order')
            require(all(value is None or times[event] is not None for value,event in zip(categories,[2,4])) and (boolean(m[9]) is None or times[3] is not None),'rpc-results-have-actual-events')
            require(categories[1] is None or categories[1]>=9 or times[2] is not None,'successful-facade-has-worker-return')
        # Reply-send and facade can race after worker return: no invented total ordering.
        result['rpc'].append({'operation_ordinal':i,'stage_us':dict(zip(RPC_STAGES,times)),'deadline_relation':dict(zip(RPC_STAGES,[relation(t,lo,hi) for t in times])),'worker_result':None if categories[0] is None else RPC_RESULTS[categories[0]],'facade_result':None if categories[1] is None else RPC_RESULTS[categories[1]],'reply_send_accepted':boolean(m[9])})
    result['all_milestones_observed']=known and all(row is not None and all(t is not None for t in row['milestone_us'].values()) for row in rows)
    return result

def parser_controls():
    name='native::exact';header='native5-consent-timing known=true loss_mask=0 snapshot_available=true'
    wait='native5-consent-wait constructed_before_us=Some(1) constructed_after_us=Some(3) deadline_lower_us=Some(15000001) deadline_upper_us=Some(15000003) outcome_ok=Some(false) observed_us=Some(15001000) exact_deadline_known=false'
    slot='native5-consent-slot index=0 observation=Some(([Some(0), Some(2), Some(4), Some(5), None, None, None, None, None], [None, None, None, None, None], 0))'
    rpc='native5-consent-rpc index=0 times=[Some(0), Some(1), Some(2), Some(4), Some(3)] results=[Some(4), Some(4)] sent=Some(true)'
    proof='native5-consent-proof index=0 observation=None'
    progress='native5-consent-progress index=0 observation=Some(([None, None, None, None, None], [0, 0, 0, 0, 0]))'
    sample='\n'.join([header,wait,slot,slot.replace('index=0','index=1'),slot.replace('index=0','index=2'),proof,proof.replace('index=0','index=1'),proof.replace('index=0','index=2'),progress,progress.replace('index=0','index=1'),progress.replace('index=0','index=2'),'native5-consent-rpc-count count=1',rpc])
    unavailable='native5-consent-timing known=false loss_mask=1 snapshot_available=false'
    positives=['', 'unrelated runtime output is discarded',sample,unavailable,sample.replace('known=true loss_mask=0','known=false loss_mask=2'),sample.replace(slot,'native5-consent-slot index=0 observation=None').replace(progress,'native5-consent-progress index=0 observation=None'),'test '+name+' ... '+sample,sample.replace('results=[Some(4), Some(4)]','results=[Some(9), Some(10)]')]
    for s in positives:timing(s,name)
    require(timing('',name)['observed'] is False and timing('',name)['known'] is False and timing('',name)['loss_mask'] is None and timing('',name)['slots'] is None,'missing-report-remains-unobserved-unknown')
    require(not timing(sample,name)['all_milestones_observed'] and timing(unavailable,name)['rpc'] is None,'unknown-never-complete')
    bad=[sample+'\n'+header,sample.replace('index=2','index=1'),sample.replace('Some(15000003)','Some(15000004)'),sample.replace('exact_deadline_known=false','exact_deadline_known=true'),sample.replace('Some(0)','Some(-1)',1),sample.replace('Some(0)','Some(600000001)',1),sample.replace('loss_mask=0','loss_mask=128'),unavailable.replace('known=false','known=true'),sample.replace('Some(false)','Some(Failed)'),sample.replace('], 0))','], 4294967296))'),sample.replace('observation=Some((', 'observation=Some(',1),sample.replace('snapshot_available=true','snapshot_available=false'),sample.replace('count=1','count=0'),sample.replace('count=1','count=129'),sample+'\n'+rpc,sample.replace('results=[Some(4), Some(4)]','results=[Some(11), Some(4)]'),sample.replace('sent=Some(true)','sent=Some(secret)'),sample.replace('times=[Some(0)','times=[Some(-1)'),sample.replace('index=0 times=','index=1 times='),'test foreign::case ... '+sample,sample+'\nnative5-consent-private secret',sample.replace('index=2 observation','index=3 observation'),
        sample.replace('Some(0), Some(2), Some(4), Some(5)','Some(0), Some(4), Some(2), Some(5)'),
        sample.replace('[None, None, None, None, None], 0))','[Some(true), None, None, None, None], 0))'),
        sample.replace('times=[Some(0), Some(1), Some(2), Some(4), Some(3)]','times=[Some(0), Some(2), Some(1), Some(4), Some(3)]'),
        sample.replace('times=[Some(0), Some(1), Some(2), Some(4), Some(3)]','times=[Some(0), Some(1), None, Some(4), Some(3)]'),
        sample.replace('observed_us=Some(15001000)','observed_us=Some(2)')]
    for s in bad:
        try:timing(s,name)
        except ValueError:continue
        raise ValueError('adversarial-timing-shape-accepted')
    proof_partial='native5-consent-proof index=0 observation=Some((false, [None, None, None, None, None, None, None, None, None], [None, None, None, None, None], [Some(10), None, None, None], 2, [None, None, None, None, None, None]))'
    progress_partial='native5-consent-progress index=0 observation=Some(([Some(6), Some(7), Some(8), None, None], [0, 0, 0, 0, 0]))'
    partial=sample.replace(proof,proof_partial).replace(progress,progress_partial)
    complete_proof='native5-consent-proof index=0 observation=Some((true, [Some(14), Some(15), Some(16), Some(17), Some(18), Some(19), Some(21), Some(20), Some(22)], [Some(true), Some(true), Some(true), Some(true), Some(true)], [Some(10), Some(11), Some(12), Some(13)], 0, [Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]))'
    progress_complete='native5-consent-progress index=0 observation=Some(([Some(6), Some(7), Some(8), Some(9), Some(23)], [0, 0, 0, 0, 0]))'
    complete=sample.replace(proof,complete_proof).replace(progress,progress_complete)
    race=complete.replace('[Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]','[Some(15), Some(15), Some(15), Some(15), Some(15), Some(15)]')
    for value in [partial,complete,race]:timing(value,name)
    extra_bad=[partial.replace('Some((false,','Some((true,',1),partial.replace('[Some(10), None, None, None]','[Some(10), None, Some(12), None]'),partial.replace('], 2, [','], 4294967296, ['),complete.replace('index=2 observation=None','index=1 observation=None'),complete.replace('Some(13)], 0, [','Some(15)], 0, ['),complete.replace('Some(18), Some(19)','Some(19), Some(18)'),complete.replace('Some(9), Some(23)','None, Some(23)'),complete.replace('Some(8), Some(9), Some(23)','Some(8), Some(24), Some(23)'),complete.replace('], [0, 0, 0, 0, 0]))','], [0, 0, -1, 0, 0]))'),partial.replace(progress_partial,progress),complete.replace('native5-consent-progress index=0 observation=Some(', 'native5-consent-progress index=0 observation=Some(secret',1)]
    extra_bad += [complete.replace('[Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]','[Some(15), Some(15), Some(15), Some(15), Some(18), Some(19)]'), complete.replace('[Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]','[Some(15), None, Some(15), Some(15), Some(15), Some(17)]'), complete.replace('[Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]','[Some(14), Some(15), Some(15), Some(15), Some(15), Some(17)]')]
    for value in extra_bad:
        try:timing(value,name)
        except ValueError:continue
        raise ValueError('adversarial-proof-progress-shape-accepted')
    return {'positive':len(positives)+3,'negative':len(bad)+len(extra_bad),'actual_runtime_bodies':0}

