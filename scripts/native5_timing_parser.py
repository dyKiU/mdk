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
            'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,'terminal_validation_cost':None,'peer_proofs':None,'peer_progress':None,'incoming_peer_proof':None,
            'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,
            'missing_is_not_zero':True,'missing_peer_observation_is_unknown':True,'all_milestones_observed':False,'missing_reason':'NoOwnedProbeReport','sdk_publication':sdk_timing(raw,name,None,None,None,None)}
    require(len(lines)<=156 and all(len(s)<4096 for s in lines),'bounded-lines')
    h=re.fullmatch(r'native5-consent-timing known=(true|false) loss_mask=('+N+r') snapshot_available=(true|false)',lines[0]);require(h is not None,'closed-header')
    known=h[1]=='true';loss=number(h[2],127);available=h[3]=='true'
    require(known==(loss==0) and (available or not known),'loss-unknown-semantics')
    result={'observed':True,'known':known,'loss_mask':loss,'snapshot_available':available,'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,'terminal_validation_cost':None,'peer_proofs':None,'peer_progress':None,'incoming_peer_proof':None,'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,'missing_is_not_zero':True,'missing_peer_observation_is_unknown':True,'all_milestones_observed':False}
    result['sdk_publication']=sdk_timing(raw,name,None,None,None,None)
    if not available:require(len(lines)==1,'no-invented-unavailable-rows');return result
    require(len(lines)>=27,'three-channel-phase-slots-and-rpc-count')
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
    peer_proof_pattern=proof_pattern.replace('native5-consent-proof','native5-consent-peer-proof')
    peer_proofs=[]
    for i,line in enumerate(lines[11:14]):
        m=re.fullmatch(peer_proof_pattern,line);require(m is not None and int(m[1])==i,'exact-three-peer-proof-indices')
        if line.endswith('observation=None'):peer_proofs.append(None);continue
        bound=m[2]=='true';times=[opt(m[j]) for j in range(3,12)];flags=[boolean(m[j]) for j in range(12,17)];preparation=[opt(m[j]) for j in range(17,21)];retries=number(m[21],4294967295);spawn=[opt(m[j]) for j in range(22,28)]
        if known:
            require(rows[i] is not None and preparation[0] is not None,'peer-proof-matches-selected-recipient-channel')
            require(bound==(times[0] is not None),'peer-real-first-message-binding')
            require(bound or all(value is None for value in times+flags),'peer-unbound-no-publication')
            require(ordered_observed(preparation) and all(value is None or all(v is not None for v in preparation[:j]) for j,value in enumerate(preparation)),'peer-seal-wrap-prefix')
            require(times[0] is None or preparation[3] is not None and preparation[3]<=times[0],'peer-wrap-before-prepared')
            require(ordered_observed(times[:6]) and ordered_observed(times[7:9]),'peer-publication-partial-order')
            require(all(flag is None or times[event] is not None for flag,event in zip(flags,[4,4,6,7,8])),'peer-outcome-actual-event')
            require(times[5] is None or flags[0] is True and flags[1] is True,'peer-ack-real-success')
            require(ordered_observed(spawn) and all(value is None or all(v is not None for v in spawn[:j]) for j,value in enumerate(spawn)),'peer-spawn-parent-prefix')
            require(all(v is None for v in spawn) or bound and times[1] is not None and times[1]<=next(v for v in spawn if v is not None),'peer-spawn-after-validation')
            require(times[2] is None or spawn[4] is not None and spawn[4]<=times[2],'peer-task-after-before-spawn')
        peer_proofs.append({'first_attempt_actual_message_bound':bound,'milestone_us':dict(zip(MILESTONES,times)),'deadline_relation':dict(zip(MILESTONES,[relation(t,lo,hi) for t in times])),'outcomes':dict(zip(OUTCOMES,flags)),'preparation_us':dict(zip(PROOF_PREPARATION,preparation)),'spawn_boundary_us':dict(zip(SPAWN_BOUNDARIES,spawn)),'subsequent_proof_attempts':retries,'later_attempt_events_are_not_merged':True})
    result['peer_proofs']=peer_proofs
    labels=['consent_route','core_bind_call','core_bind_success','ready_write','policy_first_call','policy_commit_success','proof_eligibility']
    pattern=r'native5-consent-peer-progress index=([012]) observation=(?:None|Some\(\(\['+', '.join(['('+ON+')']*7)+r'\], \['+', '.join(['('+N+')']*7)+r'\], \['+', '.join(['('+N+')']*2)+r'\], \['+', '.join(['('+N+')']*8)+r'\]\)\))'
    peer_progress=[]
    for i,line in enumerate(lines[14:17]):
        m=re.fullmatch(pattern,line);require(m is not None and int(m[1])==i,'exact-peer-progress-indices')
        if line.endswith('observation=None'):peer_progress.append(None);continue
        times=[opt(m[j]) for j in range(2,9)];repeats=[number(m[j],4294967295) for j in range(9,16)];bind=[number(m[j],4294967295) for j in range(16,18)];validation=[number(m[j],4294967295) for j in range(18,26)]
        if known:
            require(rows[i] is not None,'peer-progress-common-context-channel')
            require(ordered_observed(times[:4]) and all(v is None or all(p is not None for p in times[:j]) for j,v in enumerate(times[:4])),'peer-consent-prefix')
            require(times[5] is None or times[4] is not None and times[4]<=times[5],'peer-policy-after-call')
            require(times[2] is None or bind[0]>0,'peer-bound-consent-real-result')
        peer_progress.append({'first_observed_us':dict(zip(labels,times)),'deadline_relation':dict(zip(labels,[relation(t,lo,hi) for t in times])),'subsequent_observation_counts':dict(zip(labels,repeats)),'core_bind_results':dict(zip(['Ok','Err'],bind)),'publication_parent_validation_results':dict(zip(['Ok','Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite'],validation)),'local_generation_compared_across_devices':False})
    result['peer_progress']=peer_progress
    pattern=r'native5-consent-incoming index=([0-8]) observation=(?:None|Some\(\(\['+', '.join(['('+ON+')']*6)+r'\], ('+OB+r'), ('+ON+r'), ('+N+r'), (None|Some\(\(('+N+r'), ('+N+r')\)\))\)\))'
    incoming=[]
    for i,line in enumerate(lines[17:26]):
        m=re.fullmatch(pattern,line);require(m is not None and int(m[1])==i,'exact-incoming-category-indices')
        if line.endswith('observation=None'):incoming.append(None);continue
        times=[opt(m[j]) for j in range(2,8)];opened=boolean(m[8]);disposition=opt(m[9],6);later=number(m[10],4294967295);accepted=None if m[11]=='None' else [number(m[12]),number(m[13],4294967295)]
        if known:
            require(rows[i//3] is not None and times[0] is not None,'incoming-real-owned-channel-route')
            if i%3==0:require(peer_proofs[i//3] is not None and peer_proofs[i//3]['preparation_us']['seal_after'] is not None and peer_progress[i//3] is not None,'same-first-wire-has-real-successful-seal-capture')
            require(ordered_observed(times[:4]),'first-contiguous-receive-order')
            require(times[2] is None or times[1] is not None,'opened-return-has-call')
            require(opened is None or times[2] is not None,'open-result-has-return')
            require(times[3] is None or opened is True,'semantic-accept-after-actual-open')
            require(disposition is None or times[5] is not None,'receive-result-has-return')
            require(ordered_observed([times[0],times[4],times[5]]),'route-rebuffer-return-order')
            require(accepted is None or accepted[1]<=later and accepted[0]>=times[0],'eventual-accept-owned-attempt')
            require(times[3] is None or accepted is not None and accepted[1]==0 and accepted[0]==times[3],'first-accept-has-separate-success')
        incoming.append({'channel_index':i//3,'wire_category':['same_first_sealed_wire','other_wire','unbound_first_sealed_wire'][i%3],'first_receive_attempt_us':dict(zip(['route','open_before','open_returned','semantic_accepted','rebuffered','handler_returned'],times)),'first_receive_open_ok':opened,'first_receive_result':None if disposition is None else ['OkTrue','OkFalse','Unsupported','NotReady','Closed','StaleRevision','RuntimeUnavailable'][disposition],'later_receive_calls':later,'first_successful_acceptance':None if accepted is None else {'observed_us':accepted[0],'receive_attempt_ordinal':accepted[1]},'receiver_outer_event_identity_known':False,'wire_equality_is_not_first_envelope_delivery':True,'later_receive_events_not_merged_into_first':True})
    result['incoming_peer_proof']=incoming
    c=re.fullmatch(r'native5-consent-rpc-count count=('+N+r')',lines[26]);require(c is not None,'closed-rpc-count');count=number(c[1],128);require(len(lines)==28+count,'all-rpc-rows-and-terminal-cost-exact')
    pattern=r'native5-consent-rpc index=('+N+r') times=\['+', '.join(['('+ON+')']*5)+r'\] results=\['+', '.join(['('+ON+')']*2)+r'\] sent=('+OB+r')'
    result['rpc']=[]
    for i,line in enumerate(lines[27:-1]):
        m=re.fullmatch(pattern,line);require(m is not None and number(m[1],127)==i,'unique-ordered-rpc-index')
        times=[opt(m[j]) for j in range(2,7)];categories=[opt(m[j],10) for j in (7,8)]
        if known:
            require(ordered_observed(times[:4]) and ordered_observed([times[0],times[4]]),'same-operation-rpc-partial-order')
            require(all(value is None or times[event] is not None for value,event in zip(categories,[2,4])) and (boolean(m[9]) is None or times[3] is not None),'rpc-results-have-actual-events')
            require(categories[1] is None or categories[1]>=9 or times[2] is not None,'successful-facade-has-worker-return')
        # Reply-send and facade can race after worker return: no invented total ordering.
        result['rpc'].append({'operation_ordinal':i,'stage_us':dict(zip(RPC_STAGES,times)),'deadline_relation':dict(zip(RPC_STAGES,[relation(t,lo,hi) for t in times])),'worker_result':None if categories[0] is None else RPC_RESULTS[categories[0]],'facade_result':None if categories[1] is None else RPC_RESULTS[categories[1]],'reply_send_accepted':boolean(m[9])})
    terminal_pattern=r'native5-consent-terminal-cost observation=\(\['+', '.join(['('+N+')']*8)+r'\], ('+N+r'), \['+', '.join(['('+ON+')']*2)+r'\]\)'
    terminal=re.fullmatch(terminal_pattern,lines[-1]);require(terminal is not None,'closed-terminal-cost')
    values=[number(terminal[j]) for j in range(1,9)];inflight=number(terminal[9],1000000);first,last=[opt(terminal[j]) for j in (10,11)]
    started,completed,errors,total,maximum,before_count,before_total,before_max=values
    require(started<=1000000 and completed<=started and errors<=completed and before_count<=completed,'terminal-count-order')
    require(started==completed+inflight and maximum<=total and before_total<=total and before_max<=maximum and before_max<=before_total,'terminal-cost-order')
    require((started>0)==(first is not None) and (completed>0)==(last is not None),'terminal-observed-bounds')
    require(first is None or after is not None and first>=after,'terminal-started-in-fourth-wait')
    require(last is None or first is not None and last>=first,'terminal-monotonic-bounds')
    require(completed>0 or total==maximum==errors==before_count==before_total==before_max==0,'terminal-empty-completions')
    require(before_count>0 or before_total==before_max==0,'terminal-empty-deadline-subset')
    result['terminal_validation_cost']={'known':known,'scope':'all-actors-terminal-no-publication-periodic-calls-started-during-current-join-wait','started':started,'completed':completed,'errors':errors,'in_flight_at_freeze':inflight,'completed_wall_total_us':total,'completed_wall_max_us':maximum,'first_start_us':first,'last_completion_us':last,'definitely_inside_deadline_completed_count':before_count,'definitely_inside_deadline_wall_total_us':before_total,'definitely_inside_deadline_wall_max_us':before_max,'wall_includes_preemption':True,'CPU_time_known':False,'inflight_duration_unknown':inflight>0,'overlapping_totals_are_not_exclusive_time':True}
    result['sdk_publication']=sdk_timing(raw,name,lo,hi,rows,proofs,peer_proofs)
    result['all_milestones_observed']=known and all(row is not None and all(t is not None for t in row['milestone_us'].values()) for row in rows)
    return result

def parser_controls():
    name='native::exact';header='native5-consent-timing known=true loss_mask=0 snapshot_available=true'
    wait='native5-consent-wait constructed_before_us=Some(1) constructed_after_us=Some(3) deadline_lower_us=Some(15000001) deadline_upper_us=Some(15000003) outcome_ok=Some(false) observed_us=Some(15001000) exact_deadline_known=false'
    slot='native5-consent-slot index=0 observation=Some(([Some(0), Some(2), Some(4), Some(5), None, None, None, None, None], [None, None, None, None, None], 0))'
    rpc='native5-consent-rpc index=0 times=[Some(0), Some(1), Some(2), Some(4), Some(3)] results=[Some(4), Some(4)] sent=Some(true)'
    proof='native5-consent-proof index=0 observation=None'
    progress='native5-consent-progress index=0 observation=Some(([None, None, None, None, None], [0, 0, 0, 0, 0]))'
    sample='\n'.join([header,wait,slot,slot.replace('index=0','index=1'),slot.replace('index=0','index=2'),proof,proof.replace('index=0','index=1'),proof.replace('index=0','index=2'),progress,progress.replace('index=0','index=1'),progress.replace('index=0','index=2'),*['native5-consent-peer-proof index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-peer-progress index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-incoming index='+str(i)+' observation=None' for i in range(9)],'native5-consent-rpc-count count=1',rpc,'native5-consent-terminal-cost observation=([0, 0, 0, 0, 0, 0, 0, 0], 0, [None, None])'])
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
    empty='native5-consent-terminal-cost observation=([0, 0, 0, 0, 0, 0, 0, 0], 0, [None, None])'
    cost='native5-consent-terminal-cost observation=([2, 1, 1, 4, 4, 1, 4, 4], 1, [Some(3), Some(7)])'
    timing(sample.replace(empty,cost),name)
    terminal_bad=[sample.replace(empty,cost.replace('[2, 1, 1','[1, 1, 1')),sample.replace(empty,cost.replace('Some(3)','Some(2)')),sample.replace(empty,cost.replace('[2, 1, 1','[2, 1, 2')),sample.replace(empty,cost.replace('4, 4], 1','4, 5], 1')),sample.replace(empty,cost.replace('Some(7)','Some(secret)')),sample+'\n'+empty,sample.replace(empty,cost.replace('[2, 1, 1','[true, 1, 1'))]
    for value in terminal_bad:
        try:timing(value,name)
        except ValueError:continue
        raise ValueError('adversarial-terminal-cost-accepted')
    reciprocal=peer_parser_controls(sample,name)
    return {'reciprocal':reciprocal,'positive':len(positives)+4,'negative':len(bad)+len(extra_bad)+len(terminal_bad),'actual_runtime_bodies':0}


SDK_STAGES=['sdk_entry','verify_before','verify_after','lease_retain_before','lease_retain_after','endpoint_task_first_poll','connect_before','connect_after','first_send_before','first_send_returned','first_attempt_receipt_constructed','lease_release_before','lease_release_after','single_call_finished','single_call_accepted_receipt']
SDK_OUTCOMES=['verified_ok','retain_ok','connect_ok','first_send_result_category','first_attempt_receipt_typed_ack','single_call_result_ok','single_call_receipt_typed_ack']
def sdk_timing(raw,name,lo,hi,slots,proofs,peer_proofs=None):
    lines=[line for line in raw.splitlines() if line.startswith('native5-sdk-')]
    if not lines:return {'observed':False,'known':False,'loss_mask':None,'slots':None,'missing_is_unknown':True}
    require(len(lines)<=10 and all(len(line)<4096 for line in lines),'bounded-sdk-report')
    h=re.fullmatch(r'native5-sdk-timing known=(true|false) loss_mask=('+N+r') snapshot_available=(true|false)',lines[0]);require(h is not None,'closed-sdk-header')
    known=h[1]=='true';loss=number(h[2],127);available=h[3]=='true'
    require(known==(loss==0) and (available or not known),'sdk-loss-unknown')
    result={'observed':True,'known':known,'loss_mask':loss,'snapshot_available':available,'slots':None,'no_identifiers_exported':True,'same_origin_as_native_clock':True,'later_calls_and_attempts_not_merged':True,'scope_drop_does_not_prove_cancellation_reason':True}
    if not available:require(len(lines)==1,'no-invented-sdk-rows');return result
    require(len(lines)==10,'nine-fixed-sdk-keys')
    pattern=r'native5-sdk-slot index=([0-8]) observation=(?:None|Some\(\((true|false), \['+', '.join(['('+ON+')']*15)+r'\], \['+', '.join(['('+ON+')']*7)+r'\], ('+ON+r'), ('+N+r'), ('+N+r'), (true|false)\)\))'
    result['slots']=[]
    for i,line in enumerate(lines[1:]):
        m=re.fullmatch(pattern,line);require(m is not None and int(m[1])==i,'closed-ordered-sdk-index')
        if line.endswith('observation=None'):result['slots'].append(None);continue
        called=m[2]=='true';times=[opt(m[j]) for j in range(3,18)];values=[opt(m[j],2 if j==21 else 1) for j in range(18,25)];route=opt(m[25],1);later_calls=number(m[26],4294967295);later_sends=number(m[27],4294967295);dropped=m[28]=='true'
        if known:
            require(called==(times[0] is not None),'sdk-call-entry-exists')
            require(called or all(value is None for value in times+values+[route]) and later_calls==later_sends==0 and not dropped,'bound-but-unobserved-sdk-call')
            require(ordered_observed(times[:11]) and ordered_observed([times[0],times[14],times[11],times[12],times[13]]),'sdk-partial-order')
            require(all(value is None or times[event] is not None for value,event in zip(values,[2,4,7,9,10,13,14])),'sdk-result-has-event')
            require(route is None or times[8] is not None,'sdk-route-at-actual-send')
            require(times[10] is None or times[9] is not None,'first-attempt-receipt-after-first-send')
            require(times[13] is None or times[12] is not None and not dropped,'sdk-finished-after-release-without-abandon')
            if slots is not None:
                channel=i//2 if i<6 else i-6
                require(slots[channel] is not None,'sdk-key-bound-to-observed-native-channel')
                if i>=6:require(peer_proofs is not None and peer_proofs[channel] is not None and peer_proofs[channel]['first_attempt_actual_message_bound'],'sdk-peer-key-is-actual-first-peer-body0')
                elif i%2:require(proofs is not None and proofs[channel] is not None and proofs[channel]['first_attempt_actual_message_bound'],'sdk-proof-key-is-actual-first-body0')
        result['slots'].append({'channel_index':i//2 if i<6 else i-6,'phase':('Consent' if i%2==0 else 'OwnBody0') if i<6 else 'PeerBody0','first_sdk_call_observed':called,'milestone_us':dict(zip(SDK_STAGES,times)),'deadline_relation':dict(zip(SDK_STAGES,[relation(t,lo,hi) for t in times])),'closed_outcome_values':dict(zip(SDK_OUTCOMES,values)),'publication_route':None if route is None else ['OpaqueClient','OwnedRelay'][route],'later_sdk_calls':later_calls,'later_send_attempts':later_sends,'scope_state':('BoundNotCalled' if not called else 'Finished' if times[13] is not None else 'DroppedBeforeFinalMarker' if dropped else 'InFlightAtFreeze'),'scope_dropped_before_final_marker':dropped,'scope_drop_reason':'Unknown' if dropped else None})
    return result

def sdk_parser_controls():
    name='native::exact';header='native5-sdk-timing known=true loss_mask=0 snapshot_available=true'
    absent=['native5-sdk-slot index='+str(i)+' observation=None' for i in range(9)]
    empty='\n'.join([header,*absent]);sdk_timing(empty,name,None,None,None,None)
    row='native5-sdk-slot index=0 observation=Some((true, [Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7), Some(8), Some(9), Some(10), Some(11), Some(13), Some(14), Some(15), Some(12)], [Some(1), Some(1), Some(1), Some(0), Some(1), Some(1), Some(1)], Some(1), 0, 0, false))'
    positive=empty.replace(absent[0],row)
    sdk_timing(positive,name,20,21,None,None)
    in_flight=positive.replace('Some(15), Some(12)', 'None, Some(12)').replace('[Some(1), Some(1), Some(1), Some(0), Some(1), Some(1), Some(1)]','[Some(1), Some(1), Some(1), Some(0), Some(1), None, Some(1)]')
    later_accepted=positive.replace('Some(11), Some(13)', 'None, Some(13)').replace('[Some(1), Some(1), Some(1), Some(0), Some(1), Some(1), Some(1)]','[Some(1), Some(1), Some(1), Some(2), None, Some(1), Some(1)]').replace('Some(1), 0, 0, false','Some(1), 0, 1, false')
    sdk_timing(in_flight,name,20,21,None,None)
    sdk_timing(later_accepted,name,20,21,None,None)
    partial='native5-sdk-slot index=0 observation=Some((true, [Some(1), Some(2), Some(3), Some(4), None, None, None, None, None, None, None, None, None, None, None], [Some(1), None, None, None, None, None, None], None, 0, 0, true))'
    sdk_timing(empty.replace(absent[0],partial),name,None,None,None,None)
    unseen='native5-sdk-slot index=0 observation=Some((false, [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None], [None, None, None, None, None, None, None], None, 0, 0, false))'
    sdk_timing(empty.replace(absent[0],unseen),name,None,None,None,None)
    sdk_timing('native5-sdk-timing known=false loss_mask=1 snapshot_available=false',name,None,None,None,None)
    sdk_timing('',name,None,None,None,None)
    negatives=[positive+'\n'+header,positive.replace('index=5','index=4'),positive.replace('Some(1), Some(2)','Some(2), Some(1)',1),positive.replace('Some(1), Some(1), Some(1), Some(0)','Some(1), Some(1), Some(1), Some(3)'),positive.replace('Some(1), 0, 0, false','Some(2), 0, 0, false'),positive.replace('0, 0, false','4294967296, 0, false'),positive.replace('0, 0, false','0, 0, true'),positive.replace('known=true loss_mask=0','known=true loss_mask=1'),positive.replace('Some(15), Some(12)','None, Some(12)'),positive.replace('Some(14), Some(15)','None, Some(15)'),positive.replace('Some(11), Some(13)','None, Some(13)'),empty.replace(absent[0],unseen.replace('0, 0, false','0, 1, false')),positive+'\nnative5-sdk-secret private',positive.replace('Some(1)','Some(secret)',1)]
    for value in negatives:
        try:sdk_timing(value,name,None,None,None,None)
        except ValueError:continue
        raise ValueError('adversarial-sdk-observation-accepted')
    return {'positive':8,'negative':len(negatives),'actual_runtime_bodies':0}


def timing_windows(raw,name):
    require(len(raw.encode())<=8*1024*1024,'bounded-two-window-output')
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    raw,prefix=re.subn(r'(?m)^test '+re.escape(name)+r' \.\.\. (?=native5-join-window begin ordinal=)','',raw)
    require(prefix<=1 and not re.search(r'(?m)^test [A-Za-z0-9_:]+ \.\.\. native5-join-window',raw),'exact-two-window-test-prefix')
    frames=[];active=None;data=[]
    for line in raw.splitlines():
        if line.startswith('native5-join-window'):
            marker=re.fullmatch(r'native5-join-window (begin|end) ordinal=([45])',line);require(marker is not None,'closed-actual-join-ordinal')
            ordinal=int(marker[2])
            if marker[1]=='begin':
                require(active is None and len(frames)<2 and ordinal==4+len(frames),'two-ordered-independent-window-begins')
                active=ordinal;data=[]
            else:
                require(active==ordinal,'same-window-end')
                parsed=timing('\n'.join(data),name)
                frames.append({'actual_join_ordinal':ordinal,'timing':parsed,'independent_origin_and_snapshot':True})
                active=None;data=[]
        elif active is not None:data.append(line)
        elif line.startswith('native5-consent-') or line.startswith('native5-sdk-'):raise ValueError('orphan-unframed-native-sdk-observation')
    require(active is None,'closed-window-before-end-of-output')
    return {'observed':bool(frames),'exact_prefix_normalizations':prefix,'windows':frames,
        'fourth':{'reached_diagnostic_arm':bool(frames),'timing':frames[0]['timing'] if frames else None},
        'fifth':{'reached_diagnostic_arm':len(frames)==2,'timing':frames[1]['timing'] if len(frames)==2 else None,'missing_reason':None if len(frames)==2 else 'NotReachedDiagnosticArm'},
        'no_cross_window_clock_or_state_merge':True,'no_joint_snapshot_claim':True}

def window_parser_controls():
    name='native::exact'
    report='\n'.join(['native5-consent-timing known=true loss_mask=0 snapshot_available=true',
        'native5-consent-wait constructed_before_us=Some(1) constructed_after_us=Some(3) deadline_lower_us=Some(15000001) deadline_upper_us=Some(15000003) outcome_ok=Some(true) observed_us=Some(5)',
        *['native5-consent-slot index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-proof index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-progress index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-peer-proof index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-peer-progress index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-incoming index='+str(i)+' observation=None' for i in range(9)],
        'native5-consent-rpc-count count=0',
        'native5-consent-terminal-cost observation=([0, 0, 0, 0, 0, 0, 0, 0], 0, [None, None])',
        'native5-sdk-timing known=true loss_mask=0 snapshot_available=true',
        *['native5-sdk-slot index='+str(i)+' observation=None' for i in range(9)]])
    # Keep the immutable existing wait wire suffix, not a changed runtime deadline.
    report=report.replace('observed_us=Some(5)','observed_us=Some(5) exact_deadline_known=false')
    fourth='native5-join-window begin ordinal=4\n'+report+'\nnative5-join-window end ordinal=4'
    fifth='native5-join-window begin ordinal=5\n'+report+'\nnative5-join-window end ordinal=5'
    both=fourth+'\n'+fifth
    unknown=fourth.replace(report,'native5-consent-timing known=false loss_mask=1 snapshot_available=false')
    for sample in ['',fourth,both,'test '+name+' ... '+both,unknown,unknown+'\n'+fifth]:timing_windows(sample,name)
    require(timing_windows(fourth,name)['fifth']['timing'] is None and timing_windows(fourth,name)['fifth']['missing_reason']=='NotReachedDiagnosticArm','absent-fifth-is-unknown-not-zero')
    require(timing_windows(unknown,name)['windows'][0]['timing']['known'] is False,'old-window-loss-remains-unknown')
    bad=[fifth,both+'\n'+fifth,fourth.replace('ordinal=4','ordinal=3'),fourth.replace('ordinal=4','ordinal=6'),fourth.replace('end ordinal=4','end ordinal=5'),fourth.replace('native5-join-window end ordinal=4',''),fourth.replace('begin ordinal=4','begin ordinal=true'),fourth+'\n'+report,'test foreign::case ... '+both,fourth.replace(report,'native5-join-window begin ordinal=5\n'+report),both.replace('begin ordinal=5','begin ordinal=4'),both.replace('native5-join-window end ordinal=5','native5-join-window end ordinal=5 private')]
    for sample in bad:
        try:timing_windows(sample,name)
        except ValueError:continue
        raise ValueError('adversarial-window-frame-accepted')
    return {'positive':6,'negative':len(bad),'actual_runtime_bodies':0}


def peer_parser_controls(sample,name):
    absent='native5-consent-incoming index=0 observation=None'
    first='native5-consent-incoming index=0 observation=Some(([Some(10), Some(11), Some(12), None, Some(13), Some(14)], Some(false), Some(3), 2, Some((19, 2))))'
    seal='native5-consent-peer-proof index=0 observation=Some((false, [None, None, None, None, None, None, None, None, None], [None, None, None, None, None], [Some(8), Some(9), None, None], 0, [None, None, None, None, None, None]))'
    ready='native5-consent-peer-progress index=0 observation=Some(([Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7)], [0, 0, 0, 0, 0, 0, 0], [1, 0], [1, 0, 0, 0, 0, 0, 0, 0]))'
    supported=sample.replace('native5-consent-peer-proof index=0 observation=None',seal).replace('native5-consent-peer-progress index=0 observation=None',ready)
    later=supported.replace(absent,first)
    timing(later,name)
    accepted=first.replace('Some(12), None, Some(13), Some(14)', 'Some(12), Some(13), None, Some(14)').replace('Some(false), Some(3), 2, Some((19, 2))','Some(true), Some(0), 0, Some((13, 0))')
    timing(supported.replace(absent,accepted),name)
    peer='native5-consent-peer-progress index=0 observation=Some(([Some(6), Some(7), None, None, None, None, None], [0, 0, 0, 0, 0, 0, 0], [0, 1], [1, 0, 0, 0, 0, 0, 0, 0]))'
    partial=sample.replace('native5-consent-peer-progress index=0 observation=None',peer)
    timing(partial,name)
    proof='native5-consent-peer-proof index=0 observation=Some((false, [None, None, None, None, None, None, None, None, None], [None, None, None, None, None], [Some(10), None, None, None], 0, [None, None, None, None, None, None]))'
    timing(partial.replace('native5-consent-peer-proof index=0 observation=None',proof),name)
    rejected=[later.replace(seal,'native5-consent-peer-proof index=0 observation=None'),later.replace('[Some(8), Some(9), None, None]','[Some(8), None, None, None]'),later.replace(ready,'native5-consent-peer-progress index=0 observation=None'),partial.replace('Some(6), Some(7)', 'Some(8), Some(7)'),partial.replace('[0, 1], [1,', '[0, true], [1,'),partial.replace('index=2 observation=None', 'index=1 observation=None'),later.replace('Some((19, 2))','Some((19, 3))'),later.replace('Some(false), Some(3)','Some(false), Some(7)'),later.replace('Some(10), Some(11)','Some(11), Some(10)'),later.replace('Some(11), Some(12)','None, Some(12)'),later.replace('index=8 observation=None','index=7 observation=None'),later+'\nnative5-consent-incoming index=0 observation=None',supported.replace(absent,accepted.replace('Some(true)','Some(false)')),supported.replace(absent,accepted.replace('Some((13, 0))','Some((13, 1))')),later.replace('Some((19, 2))','Some((secret, 2))')]
    for raw in rejected:
        try:timing(raw,name)
        except ValueError:continue
        raise ValueError('adversarial-reciprocal-observation-accepted')
    return {'positive':4,'negative':len(rejected),'actual_runtime_bodies':0}
