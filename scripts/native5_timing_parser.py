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
            'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,'terminal_validation_cost':None,'peer_proofs':None,'peer_progress':None,'incoming_peer_proof':None,'first_peer_outer_delivery':None,
            'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,
            'missing_is_not_zero':True,'missing_peer_observation_is_unknown':True,'worker_poll':safe_worker_timing(raw),'all_milestones_observed':False,'missing_reason':'NoOwnedProbeReport','sdk_publication':sdk_timing(raw,name,None,None,None,None)}
    require(len(lines)<=159 and all(len(s)<4096 for s in lines),'bounded-lines')
    h=re.fullmatch(r'native5-consent-timing known=(true|false) loss_mask=('+N+r') snapshot_available=(true|false)',lines[0]);require(h is not None,'closed-header')
    known=h[1]=='true';loss=number(h[2],127);available=h[3]=='true'
    require(known==(loss==0) and (available or not known),'loss-unknown-semantics')
    result={'observed':True,'known':known,'loss_mask':loss,'snapshot_available':available,'exact_prefix_normalizations':prefix,'wait':None,'slots':None,'proofs':None,'channel_progress':None,'rpc':None,'terminal_validation_cost':None,'peer_proofs':None,'peer_progress':None,'incoming_peer_proof':None,'first_peer_outer_delivery':None,'exact_deadline_known':False,'diagnostic_only':True,'physical_SDK_entry_observed':False,'missing_is_not_zero':True,'missing_peer_observation_is_unknown':True,'worker_poll':safe_worker_timing(raw),'all_milestones_observed':False}
    result['sdk_publication']=sdk_timing(raw,name,None,None,None,None)
    if not available:require(len(lines)==1,'no-invented-unavailable-rows');return result
    require(len(lines)>=30,'three-channel-phase-slots-and-rpc-count')
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
    delivery_pattern=r'native5-consent-first-outer-delivery index=([012]) observation=(?:None|Some\(\(('+N+r'), ('+ON+r'), ('+ON+r'), ('+OB+r'), ('+N+r')\)\))'
    deliveries=[]
    for i,line in enumerate(lines[26:29]):
        m=re.fullmatch(delivery_pattern,line);require(m is not None and int(m[1])==i,'exact-first-outer-delivery-indices')
        if line.endswith('observation=None'):deliveries.append(None);continue
        worker=number(m[2],4);delivery_before=opt(m[3]);delivery_after=opt(m[4]);ok=boolean(m[5]);later=number(m[6],4294967295)
        if known:
            require(rows[i] is not None and peer_proofs[i] is not None and peer_proofs[i]['first_attempt_actual_message_bound'],'first-outer-real-actual-message-binding')
            require(delivery_before is not None and (delivery_after is None or delivery_before<=delivery_after) and (ok is None or delivery_after is not None),'first-outer-result-bracket')
        deliveries.append({'channel_index':i,'recipient_worker_ordinal':worker,'selected_before_ingest_us':delivery_before,'ingest_returned_us':delivery_after,'first_ingest_result_ok':ok,'later_exact_outer_delivery_reselections':later,'actual_first_peer_outer_message_identity_matched':True,'recipient_original_and_child_matched':True,'content_only_AppRoute_not_automatically_same_outer_delivery':True})
    result['first_peer_outer_delivery']=deliveries
    c=re.fullmatch(r'native5-consent-rpc-count count=('+N+r')',lines[29]);require(c is not None,'closed-rpc-count');count=number(c[1],128);require(len(lines)==31+count,'all-rpc-rows-and-terminal-cost-exact')
    pattern=r'native5-consent-rpc index=('+N+r') times=\['+', '.join(['('+ON+')']*5)+r'\] results=\['+', '.join(['('+ON+')']*2)+r'\] sent=('+OB+r')'
    result['rpc']=[]
    for i,line in enumerate(lines[30:-1]):
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
    sample='\n'.join([header,wait,slot,slot.replace('index=0','index=1'),slot.replace('index=0','index=2'),proof,proof.replace('index=0','index=1'),proof.replace('index=0','index=2'),progress,progress.replace('index=0','index=1'),progress.replace('index=0','index=2'),*['native5-consent-peer-proof index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-peer-progress index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-incoming index='+str(i)+' observation=None' for i in range(9)],*['native5-consent-first-outer-delivery index='+str(i)+' observation=None' for i in range(3)],'native5-consent-rpc-count count=1',rpc,'native5-consent-terminal-cost observation=([0, 0, 0, 0, 0, 0, 0, 0], 0, [None, None])'])
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
    delivery_scope=delivery_wait_scope_controls(sample,name)
    reciprocal=peer_parser_controls(sample,name)
    worker=worker_parser_controls();capacity=worker_output_capacity_control()
    return {'delivery_wait_scope':delivery_scope,'worker':worker,'output_capacity':capacity,'reciprocal':reciprocal,'positive':len(positives)+4,'negative':len(bad)+len(extra_bad)+len(terminal_bad),'actual_runtime_bodies':0}


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
                frames.append({'actual_join_ordinal':ordinal,'timing':parsed,
                    'notification_dispositions':safe_notification_dispositions('\n'.join(data),ordinal,parsed.get('peer_proofs'),parsed.get('known') is True),
                    'intake_dispositions':safe_intake_dispositions('\n'.join(data),ordinal,parsed.get('known') is True,parsed.get('peer_proofs')),
                    'independent_origin_and_snapshot':True})
                active=None;data=[]
        elif active is not None:data.append(line)
        elif line.startswith('native5-consent-') or line.startswith('native5-sdk-') or line.startswith('native5-notification-') or line.startswith('native5-intake-'):raise ValueError('orphan-unframed-native-sdk-observation')
    require(active is None,'closed-window-before-end-of-output')
    return {'observed':bool(frames),'exact_prefix_normalizations':prefix,'windows':frames,
        'fourth':{'reached_diagnostic_arm':bool(frames),'timing':frames[0]['timing'] if frames else None,
            'notification_dispositions':frames[0]['notification_dispositions'] if frames else None,
            'intake_dispositions':frames[0]['intake_dispositions'] if frames else None},
        'fifth':{'reached_diagnostic_arm':len(frames)==2,'timing':frames[1]['timing'] if len(frames)==2 else None,
            'notification_dispositions':frames[1]['notification_dispositions'] if len(frames)==2 else None,
            'intake_dispositions':frames[1]['intake_dispositions'] if len(frames)==2 else None,'missing_reason':None if len(frames)==2 else 'NotReachedDiagnosticArm'},
        'no_cross_window_clock_or_state_merge':True,'no_joint_snapshot_claim':True}

def window_parser_controls():
    name='native::exact'
    report='\n'.join(['native5-consent-timing known=true loss_mask=0 snapshot_available=true',
        'native5-consent-wait constructed_before_us=Some(1) constructed_after_us=Some(3) deadline_lower_us=Some(15000001) deadline_upper_us=Some(15000003) outcome_ok=Some(true) observed_us=Some(5)',
        *['native5-consent-slot index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-proof index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-progress index='+str(i)+' observation=None' for i in range(3)],
        *['native5-consent-peer-proof index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-peer-progress index='+str(i)+' observation=None' for i in range(3)],*['native5-consent-incoming index='+str(i)+' observation=None' for i in range(9)],
        *['native5-consent-first-outer-delivery index='+str(i)+' observation=None' for i in range(3)],
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

WORKER_CATEGORIES=['OtherOrUninstrumented','ComparisonAdmission','SiblingPeriodic','SiblingCompletion','ClaimedDeliveryIngest','BroadMaintenance','Command']
WORKER_SAMPLE=r'(?:None|Some\(\('+', '.join([N]*7)+r', (?:true|false)\)\))'
def worker_samples(text,threads):
    require(re.fullmatch(r'\['+', '.join([WORKER_SAMPLE]*4)+r'\]',text) is not None,'four-closed-worker-samples')
    rows=[];empty=False
    for match in re.finditer(WORKER_SAMPLE,text):
        token=match[0]
        if token=='None':empty=True;rows.append(None);continue
        require(not empty,'longest-samples-contiguous')
        fields=token[6:-2].split(', ');values=[number(v) for v in fields[:7]];ordinal,start,end,thread,entry,exit,mask=values
        require(1<=ordinal<=1000000 and start<=end and thread<8 and entry<=6 and exit<=6 and mask<=127,'worker-sample-bounds')
        require(threads is None or thread<threads,'worker-anonymous-thread-observed')
        require(mask&(1<<entry)!=0,'worker-entry-category-in-selected-mask')
        rows.append({'poll_ordinal':ordinal,'enter_us':start,'return_us':end,'thread_ordinal':thread,'entry_category':WORKER_CATEGORIES[entry],'exit_category':WORKER_CATEGORIES[exit],'selected_category_mask':mask,'returned_ready':fields[7]=='true','wall_us':end-start})
    present=[row for row in rows if row is not None]
    require(len({row['poll_ordinal'] for row in present})==len(present),'unique-selected-poll-ordinals')
    require([(-row['wall_us'],row['poll_ordinal']) for row in present]==sorted((-row['wall_us'],row['poll_ordinal']) for row in present),'longest-sample-order')
    return rows

def worker_timing(raw):
    lines=[line for line in raw.splitlines() if line.startswith('native5-worker-')]
    result={'observed':bool(lines),'known':False,'loss_mask':None,'spawned_workers':None,'observed_thread_count':None,'workers':None,'focus':None,'same_origin_as_native':True,'no_joint_snapshot_claim':True,'wall_is_not_CPU':True,'between_polls_is_not_proven_ready_queue_delay':True,'top_samples_are_not_complete_event_log':True,'mixed_mask_does_not_attribute_whole_poll_to_one_arm':True,'focus_is_online_candidate_sampling_refiltered_at_independent_endpoint_snapshot':True}
    if not lines:return result
    require(len(lines)==21 and all(len(line)<4096 for line in lines),'fixed-worker-report-size')
    h=re.fullmatch(r'native5-worker-meta known=(true|false) loss_mask=('+N+r') spawned=('+N+r') threads=('+ON+r') endpoints=\['+', '.join(['('+ON+')']*6)+r'\]',lines[0]);require(h is not None,'closed-worker-header')
    loss=number(h[2],127);known=h[1]=='true';spawned=number(h[3],1000000);threads=opt(h[4],8);endpoints=[opt(h[j]) for j in range(5,11)]
    require(known==(loss==0) and (not known or spawned==5 and threads is not None),'worker-independent-loss-semantics')
    result.update(known=known,loss_mask=loss,spawned_workers=spawned,observed_thread_count=threads,workers=[],focus=[],expected_spawned_workers=5,worker_identity_is_anonymous_spawn_ordinal=True,thread_ordinals_are_per_window_only=True)
    inflight_pattern=r'(?:None|Some\(\('+', '.join([N]*4)+r'\)\))'
    samples_pattern=r'\['+', '.join([WORKER_SAMPLE]*4)+r'\]'
    pattern=r'native5-worker-poll index=([0-4]) observation=(?:None|Some\(\(\[('+N+r'(?:, '+N+r'){6})\], ('+N+r'), ('+inflight_pattern+r'), ('+samples_pattern+r')\)\))'
    for worker in range(5):
        line=lines[1+worker*4];m=re.fullmatch(pattern,line);require(m is not None and int(m[1])==worker,'five-exact-worker-indices')
        if line.endswith('observation=None'):
            require(not known,'worker-missing-not-known');row=None
        else:
            counts=[number(v) for v in m[2].split(', ')];mask=number(m[3],255);inflight=None if m[4]=='None' else [number(v) for v in m[4][6:-2].split(', ')];samples=worker_samples(m[5],threads)
            started,completed,pending,ready,unfinished,total,maximum=counts
            if known:
                require(started<=1000000 and started==completed+unfinished and unfinished<=1 and completed==pending+ready,'worker-actual-count-closure')
                require(maximum<=total and (completed>0 or total==maximum==0),'worker-wall-closure')
                require(bool(unfinished)==(inflight is not None),'worker-unfinished-not-zero')
                require(threads is not None and mask<(1<<threads) and (started>0 or mask==0),'worker-thread-bitmap-bounds')
                if inflight:require(inflight[0]==started and inflight[2]<threads and inflight[3]<=6,'worker-current-poll-bounds')
                require(all(sample is None or sample['poll_ordinal']<=completed and sample['wall_us']<=maximum for sample in samples),'worker-samples-completed-only')
            row={'worker_ordinal':worker,'observed_poll_count':started,'completed_poll_count':completed,'pending_returns':pending,'ready_returns':ready,'unfinished_at_freeze':unfinished,'completed_wall_total_us':total,'completed_wall_max_us':maximum,'observed_thread_ordinal_mask':mask,'unfinished_poll':None if inflight is None else dict(zip(['ordinal','enter_us','thread_ordinal','entry_category'],inflight)),'four_longest_completed_polls':samples}
        result['workers'].append(row)
        for channel in range(3):
            line=lines[2+worker*4+channel];m=re.fullmatch(r'native5-worker-focus worker=([0-4]) channel=([012]) observation=(None|Some\(('+samples_pattern+r')\))',line);require(m is not None and int(m[1])==worker and int(m[2])==channel,'exact-worker-channel-focus')
            samples=None if m[3]=='None' else worker_samples(m[4],threads)
            ack,route=endpoints[channel*2:channel*2+2]
            if known:
                require((samples is not None)==(row is not None),'worker-focus-same-snapshot-row')
                require(samples is None or all(sample is None or ack is not None and sample['return_us']>=ack and (route is None or ack<=route and sample['enter_us']<=route) for sample in samples),'focus-actual-native-ACK-route-overlap')
                require(samples is None or all(sample is None or sample['poll_ordinal']<=row['completed_poll_count'] for sample in samples),'focus-completed-not-inflight')
            result['focus'].append({'worker_ordinal':worker,'channel_index':channel,'native_accepted_ack_us':ack,'same_first_sealed_wire_AppRoute_us':route,'first_outer_event_route_identity_known':False,'interval_scope':'native-peer-acceptedACK-to-content-matched-AppRoute','four_longest_overlapping_completed_polls':samples})
    return result

def worker_parser_controls():
    header='native5-worker-meta known=true loss_mask=0 spawned=5 threads=Some(1) endpoints=[Some(2), Some(5), None, None, None, None]'
    samples='[Some((1, 1, 4, 0, 0, 0, 1, false)), None, None, None]'
    rows=[]
    for worker in range(5):
        rows.append('native5-worker-poll index='+str(worker)+' observation=Some(([1, 1, 1, 0, 0, 3, 3], 1, None, '+samples+'))')
        for channel in range(3):rows.append('native5-worker-focus worker='+str(worker)+' channel='+str(channel)+' observation=Some('+(samples if channel==0 else '[None, None, None, None]')+')')
    sample='\n'.join([header,*rows]);worker_timing(sample)
    inflight=sample.replace('[1, 1, 1, 0, 0, 3, 3], 1, None','[2, 1, 1, 0, 1, 3, 3], 1, Some((2, 5, 0, 0))')
    worker_timing(inflight);worker_timing(sample.replace('known=true loss_mask=0','known=false loss_mask=1'));worker_timing('')
    bad=[sample.replace('spawned=5','spawned=6'),sample.replace('threads=Some(1)','threads=None'),sample.replace('index=4','index=3'),sample.replace('Some((1, 1, 4','Some((1, 4, 1'),sample.replace('[1, 1, 1, 0, 0','[1, 1, 0, 0, 0'),sample.replace('0, 0, 1, false','0, 0, 128, false'),sample.replace('Some(2), Some(5)','None, Some(5)'),sample+'\n'+header,inflight.replace('Some((2, 5, 0, 0))','None'),sample.replace('3, 3], 1, None','3, 4], 1, None'),sample.replace('Some((1, 1, 4, 0','Some((1, 1, 4, 1')]
    for raw in bad:
        try:worker_timing(raw)
        except ValueError:continue
        raise ValueError('adversarial-worker-poll-observation-accepted')
    return {'positive':4,'negative':len(bad),'actual_runtime_bodies':0}

def worker_output_capacity_control():
    # Maximum-width closed fields, not invented runtime evidence. Deliberately
    # repeated sample ordinals measure serialization capacity only.
    def array(value,count):return '['+', '.join([value]*count)+']'
    stamp='Some(600000000)';flag='Some(false)';counter='4294967295'
    publication='Some(('+array(stamp,9)+', '+array(flag,5)+', '+counter+'))'
    proof='Some((false, '+array(stamp,9)+', '+array(flag,5)+', '+array(stamp,4)+', '+counter+', '+array(stamp,6)+'))'
    native=['native5-consent-timing known=false loss_mask=127 snapshot_available=true','native5-consent-wait constructed_before_us='+stamp+' constructed_after_us='+stamp+' deadline_lower_us=Some(615000000) deadline_upper_us=Some(615000000) outcome_ok='+flag+' observed_us='+stamp+' exact_deadline_known=false']
    for label,value in [('slot',publication),('proof',proof),('progress','Some(('+array(stamp,5)+', '+array(counter,5)+'))'),('peer-proof',proof),('peer-progress','Some(('+array(stamp,7)+', '+array(counter,7)+', '+array(counter,2)+', '+array(counter,8)+'))')]:
        native.extend('native5-consent-'+label+' index='+str(i)+' observation='+value for i in range(3))
    native.extend('native5-consent-incoming index='+str(i)+' observation=Some(('+array(stamp,6)+', '+flag+', Some(6), '+counter+', Some((600000000, '+counter+'))))' for i in range(9))
    native.extend('native5-consent-first-outer-delivery index='+str(i)+' observation=Some((4, '+stamp+', '+stamp+', '+flag+', '+counter+'))' for i in range(3))
    native.append('native5-consent-rpc-count count=128')
    native.extend('native5-consent-rpc index='+str(i)+' times='+array(stamp,5)+' results=[Some(10), Some(10)] sent='+flag for i in range(128))
    native.append('native5-consent-terminal-cost observation=('+array('600000000',8)+', 1000000, '+array(stamp,2)+')')
    sdk=['native5-sdk-timing known=false loss_mask=127 snapshot_available=true']
    sdk.extend('native5-sdk-slot index='+str(i)+' observation=Some((false, '+array(stamp,15)+', '+array('Some(2)',7)+', Some(1), '+counter+', '+counter+', false))' for i in range(9))
    sample='Some((1000000, 600000000, 600000000, 7, 6, 6, 127, false))';samples=array(sample,4)
    worker=['native5-worker-meta known=false loss_mask=127 spawned=18446744073709551615 threads=Some(8) endpoints='+array(stamp,6)]
    for index in range(5):
        worker.append('native5-worker-poll index='+str(index)+' observation=Some(('+array('600000000',7)+', 255, Some((1000000, 600000000, 7, 6)), '+samples+'))')
        worker.extend('native5-worker-focus worker='+str(index)+' channel='+str(channel)+' observation=Some('+samples+')' for channel in range(3))
    notification=notification_maximum_width_appendix();intake=intake_maximum_width_appendix()
    report='\n'.join(native+sdk+worker+notification+intake)+'\n'
    require(len(native)==159 and len(sdk)==10 and len(worker)==21 and len(notification)==16 and len(intake)==94 and all(len(line)<4096 for line in native+sdk+worker+notification+intake),'maximum-closed-report-shape')
    require(len(report.encode())<=65536,'existing-64KiB-output-capacity')
    return {'maximum_width_serialized_bytes':len(report.encode()),'existing_cap_bytes':65536,'maximum_RPC_rows':128,'maximum_notification_rows':15,'maximum_intake_rows':93,'maximum_intake_appendix_bytes':len(('\n'.join(intake)+'\n').encode()),'maximum_notification_appendix_bytes':len(('\n'.join(notification)+'\n').encode()),'maximum_longest_poll_samples':20,'maximum_focus_candidates':60,'runtime_bodies':0,'capacity_fixture_is_not_runtime_evidence':True}


def safe_worker_timing(raw):
    try:return worker_timing(raw)
    except ValueError:return {'observed':True,'known':False,'loss_mask':None,'workers':None,'focus':None,'parser_failure_category':'ClosedWorkerSchemaRejected','protocol_ledger_retained':True,'no_joint_snapshot_claim':True}

def delivery_wait_scope_controls(sample,name):
    # A completed real-shaped outer delivery is later than the unrelated
    # terminal-call start, while both follow the ORIGINAL wait construction.
    peer='native5-consent-peer-proof index=0 observation=Some((true, [Some(14), Some(15), Some(16), Some(17), Some(18), Some(19), Some(21), Some(20), Some(22)], [Some(true), Some(true), Some(true), Some(true), Some(true)], [Some(10), Some(11), Some(12), Some(13)], 0, [Some(15), Some(15), Some(15), Some(15), Some(15), Some(17)]))'
    progress='native5-consent-peer-progress index=0 observation=Some(([Some(1), Some(2), Some(3), Some(4), Some(5), Some(6), Some(7)], [0, 0, 0, 0, 0, 0, 0], [1, 0], [1, 0, 0, 0, 0, 0, 0, 0]))'
    delivery='native5-consent-first-outer-delivery index=0 observation=Some((0, Some(100), Some(101), Some(true), 0))'
    cost='native5-consent-terminal-cost observation=([1, 1, 0, 1, 1, 1, 1, 1], 0, [Some(4), Some(5)])'
    report=sample.replace('native5-consent-peer-proof index=0 observation=None',peer).replace('native5-consent-peer-progress index=0 observation=None',progress).replace('native5-consent-first-outer-delivery index=0 observation=None',delivery).replace('native5-consent-terminal-cost observation=([0, 0, 0, 0, 0, 0, 0, 0], 0, [None, None])',cost)
    restored=timing(report,name)
    require(restored['wait']['constructed_after_us']==3 and restored['first_peer_outer_delivery'][0]['ingest_returned_us']==101 and restored['terminal_validation_cost']['first_start_us']==4,'distinct-original-wait-delivery-terminal-times')
    import inspect
    fixed="worker=number(m[2],4);delivery_before=opt(m[3]);delivery_after=opt(m[4]);ok=boolean(m[5]);later=number(m[6],4294967295)"
    source=inspect.getsource(timing)
    require(source.count(fixed)==1,'counterfactual-exact-delivery-binding')
    # Recreate ONLY the historical variable shadow, in a remote parser-control
    # namespace. No input file/product/module state is changed.
    begin=source.index("    delivery_pattern=");end=source.index("    result['first_peer_outer_delivery']=deliveries",begin)
    segment=source[begin:end]
    mutant=source[:begin]+segment.replace('delivery_before','before').replace('delivery_after','after')+source[end:]
    namespace=dict(globals());exec(compile(mutant,'<remote-delivery-shadow-counterfactual>','exec'),namespace)
    try:namespace['timing'](report,name)
    except ValueError as error:require(str(error)=='terminal-started-in-fourth-wait','historical-shadow-sole-intended-gate')
    else:raise ValueError('historical-shadow-counterfactual-survived')
    require(timing(report,name)['terminal_validation_cost']['first_start_us']==4,'restored-original-wait-invariant')
    bad=report.replace('[Some(4), Some(5)]','[Some(2), Some(5)]')
    try:timing(bad,name)
    except ValueError as error:require(str(error)=='terminal-started-in-fourth-wait','actual-before-wait-still-rejected')
    else:raise ValueError('terminal-invariant-weakened')
    return {'positive':2,'negative':2,'historical_shadow_parser_counterfactual_rejected':True,'original_wait_invariant_unchanged':True,'actual_runtime_bodies':0}


# Notification disposition appendix: separate from the inherited timing schema.
# Counts and first dispatcher-observer clocks are not delivery/authority proofs.
NOTIFICATION_COUNTERS = [
    'event_handler_entered', 'raw_message_event', 'adapter_ok_zero',
    'adapter_ok_nonzero', 'adapter_error', 'plane_router_inlet',
    'no_account_delivery_route', 'account_delivery_route_present',
]
PLACEMENT_COUNTERS = ['queue_accepted','queue_full','queue_closed','spill_offered','spill_rejected','omitted']
U64 = r'(?:0|[1-9][0-9]{0,19})'
U64_MAX = 18446744073709551615
NOTIFICATION_OPTION = r'(?:None|Some\(\[' + U64 + r'(?:, ' + U64 + r'){7}\]\))'
NOTIFICATION_TIMES = r'(?:None|Some\(\[' + ON + r'(?:, ' + ON + r'){7}\]\))'
PLACEMENT_OPTION = r'(?:None|Some\(\[' + U64 + r'(?:, ' + U64 + r'){5}\]\))'
PLACEMENT_TIMES = r'(?:None|Some\(\[' + ON + r'(?:, ' + ON + r'){5}\]\))'
NOTIFICATION_MASK = r'(?:None|Some\((?:0|[1-9][0-9]{0,2})\))'


def notification_dispositions(raw, ordinal, peer_proofs, required=False, native_known=True):
    require(type(ordinal) is int and ordinal in {4,5}, 'notification-join-ordinal')
    require(type(native_known) is bool, 'notification-native-known-flag')
    require(len(raw.encode()) <= 8*1024*1024, 'notification-bounded-input')
    lines = [line for line in raw.splitlines() if line.startswith('native5-notification-')]
    if not lines:
        require(not required, 'notification-required-appendix-missing')
        return {'observed':False, 'schema_complete':False, 'source_ids_snapshot_available':None,
            'source_id_bound':None, 'rows':None, 'missing_reason':'MissingAppendix',
            'none_is_unknown_not_no_arrival':True, 'sequential_postwait_not_joint_deadline_snapshot':True}
    require(len(lines) == 16 and all(len(line.encode()) <= 1024 for line in lines), 'notification-exact-header-and-fifteen-rows')
    header = re.fullmatch(r'native5-notification-meta source_ids_snapshot_available=(true|false) source_id_bound=\[('
        + OB + '), (' + OB + '), (' + OB + r')\]', lines[0])
    require(header is not None, 'notification-exact-header')
    available = header[1] == 'true'
    bindings = [boolean(header[index]) for index in range(2,5)]
    if available:
        require(all(type(value) is bool for value in bindings), 'notification-available-bindings-must-be-known')
        if native_known:
            require(isinstance(peer_proofs,list) and len(peer_proofs) == 3, 'notification-native-proof-snapshot-required')
        for index, proof in enumerate(peer_proofs if native_known else []):
            require(proof is None or (isinstance(proof,dict) and type(proof.get('first_attempt_actual_message_bound')) is bool),
                'notification-closed-native-proof-binding')
            actual = proof['first_attempt_actual_message_bound'] if proof is not None else False
            require(bindings[index] is actual, 'notification-same-first-proof-binding')
    else:
        require(bindings == [None,None,None], 'notification-unavailable-bindings-unknown')
    rows = []
    for index, line in enumerate(lines[1:]):
        match = re.fullmatch(r'native5-notification-disposition plane=([0-4]) channel=([0-2]) counts=('
            + NOTIFICATION_OPTION + r') first_us=(' + NOTIFICATION_TIMES + r') clock_invalid_mask=(' + NOTIFICATION_MASK + r') placement_counts=(' + PLACEMENT_OPTION + r') placement_first_us=(' + PLACEMENT_TIMES + r') placement_clock_invalid_mask=(' + NOTIFICATION_MASK + ')', line)
        require(match is not None and (int(match[1]),int(match[2])) == (index//3,index%3),
            'notification-ordered-five-by-three-rows')
        plane,channel = int(match[1]),int(match[2])
        values = None
        if match[3] != 'None':
            values = [int(value) for value in match[3][6:-2].split(', ')]
            require(len(values) == 8 and all(0 <= value <= U64_MAX for value in values), 'notification-u64-counters')
        first = None if match[4] == 'None' else [opt(value) for value in match[4][6:-2].split(', ')]
        mask = None if match[5] == 'None' else int(match[5][5:-1])
        if values is None:
            require(first is None and mask is None, 'notification-missing-entry-times-unknown')
        else:
            require(isinstance(first,list) and len(first) == 8 and type(mask) is int and 0 <= mask <= 255,
                'notification-same-entry-counts-times-mask')
            for stage,(count,stamp) in enumerate(zip(values,first)):
                invalid = bool(mask & (1 << stage))
                require((count == 0 and stamp is None and not invalid) or
                        (count > 0 and ((invalid and stamp is None) or (not invalid and stamp is not None))),
                    'notification-first-clock-count-coherence')
        placement = None if match[6] == 'None' else [int(value) for value in match[6][6:-2].split(', ')]
        placement_first = None if match[7] == 'None' else [opt(value) for value in match[7][6:-2].split(', ')]
        placement_mask = None if match[8] == 'None' else int(match[8][5:-1])
        require((placement is None) == (values is None),'notification-placement-same-registry-entry-presence')
        if placement is None:
            require(placement_first is None and placement_mask is None,'notification-missing-placement-clock-unknown')
        else:
            require(len(placement) == 6 and all(0 <= value <= U64_MAX for value in placement) and
                isinstance(placement_first,list) and len(placement_first) == 6 and type(placement_mask) is int and 0 <= placement_mask <= 63,
                'notification-six-placement-clocks-and-counters')
            for stage,(count,stamp) in enumerate(zip(placement,placement_first)):
                invalid=bool(placement_mask & (1<<stage))
                require((count == 0 and stamp is None and not invalid) or
                    (count > 0 and ((invalid and stamp is None) or (not invalid and stamp is not None))),
                    'notification-placement-count-clock-coherence')
        require((available and bindings[channel] is True) or values is None, 'notification-unbound-or-unavailable-row-unknown')
        rows.append({'plane':plane,'channel':channel,'recipient_plane_for_this_join':plane == ordinal-1,
            'registry_entry_observed':values is not None,'counters':None if values is None else dict(zip(NOTIFICATION_COUNTERS,values)),
            'first_dispatcher_stage_us':None if first is None else dict(zip(NOTIFICATION_COUNTERS,first)),
            'clock_invalid_mask':mask,'placement_counters':None if placement is None else dict(zip(PLACEMENT_COUNTERS,placement)),
            'placement_first_dispatcher_us':None if placement_first is None else dict(zip(PLACEMENT_COUNTERS,placement_first)),
            'placement_clock_invalid_mask':placement_mask,'queue_accepted_does_not_mean_dequeued':True,
            'spill_offered_does_not_mean_durable':True,'stage_clocks_are_socket_arrival_times':False,
            'counts_and_first_instants_from_same_entry_mutex':True})
    return {'observed':True,'schema_complete':True,'source_ids_snapshot_available':available,
        'source_id_bound':bindings,'native_ledger_known':native_known,'native_first_proof_crossbinding_verified':available and native_known,
        'source_binding_flags_crosschecked':available and native_known,
        'supplemental_counter_facts_remain_separate_when_native_unknown':True,
        'recipient_plane':ordinal-1,'rows':rows,'counter_scope':'existing canonical registry counters for exact immutable first-proof key',
        'none_is_unknown_not_no_arrival':True,'registry_capacity':512,
        'registry_observation_does_not_establish_native_acceptance_or_authority':True,
        'sequential_postwait_not_joint_deadline_snapshot':True,'IDs_exported':False}


def safe_notification_dispositions(raw,ordinal,peer_proofs,native_known):
    try:
        return notification_dispositions(raw,ordinal,peer_proofs,native_known=native_known)
    except ValueError:
        return {'observed':any(line.startswith('native5-notification-') for line in raw.splitlines()),
            'schema_complete':False,'source_ids_snapshot_available':None,'source_id_bound':None,'rows':None,
            'failure_category':'ClosedNotificationSchemaRejected','none_is_unknown_not_no_arrival':True,
            'sequential_postwait_not_joint_deadline_snapshot':True,'inherited_native_SDK_worker_ledger_retained':True}


def notification_parser_controls():
    def appendix(available=True, bindings=None, observations=None, stamps=None):
        bindings = ['Some(true)','Some(false)','Some(false)'] if bindings is None else bindings
        observations = {} if observations is None else observations
        stamps = {} if stamps is None else stamps
        rows = ['native5-notification-meta source_ids_snapshot_available='+str(available).lower()+' source_id_bound=['+', '.join(bindings)+']']
        for plane in range(5):
            for channel in range(3):
                counts = observations.get((plane,channel),'None')
                first,mask = stamps.get((plane,channel),('None','None') if counts == 'None' else ('Some(['+', '.join(['None']*8)+'])','Some(0)'))
                rows.append('native5-notification-disposition plane='+str(plane)+' channel='+str(channel)+' counts='+counts+' first_us='+first+' clock_invalid_mask='+mask+' placement_counts='+('None' if counts == 'None' else 'Some([0, 0, 0, 0, 0, 0])')+' placement_first_us='+('None' if counts == 'None' else 'Some([None, None, None, None, None, None])')+' placement_clock_invalid_mask='+('None' if counts == 'None' else 'Some(0)'))
        return '\n'.join(rows)
    proofs = [{'first_attempt_actual_message_bound':True},None,None]
    baseline = appendix()
    row = notification_dispositions(baseline,4,proofs,True)
    require(row['schema_complete'] and row['recipient_plane'] == 3 and all(value['counters'] is None for value in row['rows']),
        'notification-bound-unknown-registration-is-not-no-arrival')
    zero = appendix(observations={(3,0):'Some([0, 0, 0, 0, 0, 0, 0, 0])'})
    require(notification_dispositions(zero,4,proofs,True)['rows'][9]['registry_entry_observed'], 'notification-actual-registered-zero-distinct-from-None')
    unknown = appendix(False,['None']*3)
    require(notification_dispositions(unknown,5,None,True)['source_ids_snapshot_available'] is False, 'notification-unavailable-snapshot-unknown')
    false_proof = [proofs[0],{'first_attempt_actual_message_bound':False},None]
    require(notification_dispositions(baseline,4,false_proof,True)['source_id_bound'][1] is False, 'notification-unbound-native-observation-allowed')
    maximum = appendix(observations={(4,0):'Some(['+', '.join([str(U64_MAX)]*8)+'])'},
        stamps={(4,0):('Some(['+', '.join(['Some(600000000)']*8)+'])','Some(0)')})
    require(notification_dispositions(maximum,5,proofs,True)['rows'][12]['counters']['event_handler_entered'] == U64_MAX,
        'notification-exact-u64-maximum')
    require(notification_dispositions('',4,proofs)['observed'] is False, 'notification-optional-only-for-inherited-fixtures')
    bad = [baseline+'\n'+baseline.splitlines()[1], '\n'.join(baseline.splitlines()[:-1]),
        baseline.replace('plane=0 channel=0','plane=0 channel=1'),
        '\n'.join([baseline.splitlines()[0],baseline.splitlines()[2],baseline.splitlines()[1]]+baseline.splitlines()[3:]),
        baseline.replace('native5-notification-meta','native5-notification-private'),
        baseline.replace('snapshot_available=true','snapshot_available=PRIVATE'),
        baseline.replace('Some(true)','None',1), baseline.replace('Some(true)','Some(false)',1),
        unknown.replace('source_id_bound=[None','source_id_bound=[Some(true)',1),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([true, 0, 0, 0, 0, 0, 0, 0])'),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([18446744073709551616, 0, 0, 0, 0, 0, 0, 0])'),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([00, 0, 0, 0, 0, 0, 0, 0])'),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([-1, 0, 0, 0, 0, 0, 0, 0])'),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([0, 0, 0, 0, 0, 0, 0])'),
        zero.replace('Some([0, 0, 0, 0, 0, 0, 0, 0])','Some([0, 0, 0, 0, 0, 0, 0, 0, 0])'),
        baseline.replace('plane=4 channel=2 counts=None','plane=4 channel=2 counts=Some([1, 0, 0, 0, 0, 0, 0, 0])'),
        baseline.replace('plane=4 channel=2 counts=None','plane=4 channel=2 counts=None private=PAYLOAD'),
        unknown.replace('plane=0 channel=0 counts=None','plane=0 channel=0 counts=Some([0, 0, 0, 0, 0, 0, 0, 0])')]
    for value in bad:
        try:
            notification_dispositions(value,4,proofs,True)
        except ValueError:
            continue
        raise ValueError('notification-adversary-accepted')
    for value in (None,[{'first_attempt_actual_message_bound':None},None,None],
                  [{'first_attempt_actual_message_bound':1},None,None],[None,None,None]):
        try:
            notification_dispositions(baseline,4,value,True)
        except ValueError:
            continue
        raise ValueError('notification-unknown-or-mismatched-proof-binding-accepted')
    try:
        notification_dispositions('',4,proofs,True)
    except ValueError:
        pass
    else:
        raise ValueError('notification-current-runtime-missing-appendix-accepted')
    require(safe_notification_dispositions(bad[0],4,proofs,True)['schema_complete'] is False,
        'notification-safe-wrapper-keeps-inherited-ledger')
    require('PAYLOAD' not in str(safe_notification_dispositions(bad[-2],4,proofs,True)), 'notification-raw-values-never-exported')
    independent = notification_dispositions(zero,4,None,True,native_known=False)
    require(independent['rows'][9]['registry_entry_observed'] and not independent['native_first_proof_crossbinding_verified'],
        'notification-positive-counters-do-not-promote-unknown-native-identity')
    observed = appendix(observations={(3,0):'Some([1, 0, 0, 0, 0, 0, 0, 0])'},
        stamps={(3,0):('Some([Some(0), None, None, None, None, None, None, None])','Some(0)')})
    require(notification_dispositions(observed,4,proofs,True)['rows'][9]['first_dispatcher_stage_us']['event_handler_entered'] == 0,
        'notification-real-converted-zero-not-unknown-fallback')
    invalid_clock = observed.replace('Some([Some(0), None','Some([None, None').replace(' clock_invalid_mask=Some(0)',' clock_invalid_mask=Some(1)')
    require(notification_dispositions(invalid_clock,4,proofs,True)['rows'][9]['clock_invalid_mask'] == 1,
        'notification-preorigin-or-invalid-clock-explicit-None')
    clock_bad = [observed.replace('first_us=Some([Some(0), None','first_us=None IGNORESome([Some(0), None'),
        observed.replace('Some([Some(0), None','Some([Some(600000001), None'),
        observed.replace(' clock_invalid_mask=Some(0)',' clock_invalid_mask=Some(256)'),
        observed.replace(' clock_invalid_mask=Some(0)',' clock_invalid_mask=None'),
        observed.replace('Some([Some(0), None','Some([None, None'),
        observed.replace(' clock_invalid_mask=Some(0)',' clock_invalid_mask=Some(1)'),
        zero.replace('first_us=Some([None','first_us=Some([Some(1)',1),
        zero.replace(' clock_invalid_mask=Some(0)',' clock_invalid_mask=Some(1)'),
        baseline.replace('first_us=None','first_us=Some(['+', '.join(['None']*8)+'])',1)]
    for value in clock_bad:
        try:notification_dispositions(value,4,proofs,True)
        except ValueError:continue
        raise ValueError('notification-clock-adversary-accepted')
    placed=zero.replace('placement_counts=Some([0, 0, 0, 0, 0, 0])','placement_counts=Some([1, 0, 0, 0, 0, 0])').replace('placement_first_us=Some([None','placement_first_us=Some([Some(1)',1)
    require(notification_dispositions(placed,4,proofs,True)['rows'][9]['placement_counters']['queue_accepted']==1,'notification-actual-placement-positive')
    placement_bad=[placed.replace('placement_first_us=Some([Some(1)','placement_first_us=Some([None'),
        placed.replace('placement_clock_invalid_mask=Some(0)','placement_clock_invalid_mask=Some(64)'),
        placed.replace('placement_counts=Some([1','placement_counts=Some([18446744073709551616'),
        placed.replace(' placement_counts=Some([1, 0, 0, 0, 0, 0])',' placement_counts=None'),
        placed.replace('placement_first_us=Some([Some(1)','placement_first_us=Some([Some(600000001)'),
        zero.replace('placement_clock_invalid_mask=Some(0)','placement_clock_invalid_mask=Some(1)')]
    for value in placement_bad:
        try:notification_dispositions(value,4,proofs,True)
        except ValueError:continue
        raise ValueError('notification-placement-adversary-accepted')
    return {'positive':10,'negative':len(bad)+len(clock_bad)+len(placement_bad)+5,'safe_unknown_controls':2,'actual_runtime_bodies':0,
        'None_never_means_no_arrival':True,'authored_fixture_not_runtime_evidence':True}


def notification_maximum_width_appendix():
    header = 'native5-notification-meta source_ids_snapshot_available=true source_id_bound=[Some(true), Some(true), Some(true)]'
    counters = 'Some(['+', '.join([str(U64_MAX)]*8)+'])'
    rows = [header]+['native5-notification-disposition plane='+str(plane)+' channel='+str(channel)+' counts='+counters+' first_us=Some(['+', '.join(['Some(600000000)']*8)+']) clock_invalid_mask=Some(0) placement_counts=Some(['+', '.join([str(U64_MAX)]*6)+']) placement_first_us=Some(['+', '.join(['Some(600000000)']*6)+']) placement_clock_invalid_mask=Some(0)'
        for plane in range(5) for channel in range(3)]
    require(len(rows) == 16 and all(len(line.encode()) <= 1024 for line in rows), 'notification-maximum-closed-shape')
    return rows




# Additional optional ledger: never merges its loss into native/SDK/worker state.
INTAKE_SELECTION_REASONS = ['MatchedCurrentOwnerAndChild','CurrentChoiceMissing',
    'CurrentChoiceUnmatchedOrOwnerUnbound','CurrentChildMissingOrChanged']
INTAKE_GATE_SAMPLE = r'(?:None|Some\(\(' + N + r', (?:true|false)\)\))'
INTAKE_SELECTION = r'(?:None|Some\(\(' + N + r', [0-3], ' + N + r'\)\))'
INTAKE_GATE = r'(?:None|Some\(\(\[' + INTAKE_GATE_SAMPLE + r'(?:, ' + INTAKE_GATE_SAMPLE + r'){15}\], ' + N + r', ' + N + r'\)\))'
INTAKE_INGEST = r'(?:None|Some\(\(' + N + r', ' + ON + r', ' + OB + r', ' + N + r', ' + N + r'\)\))'
INTAKE_FLAGS = r'(?:true|false), (?:true|false), (?:true|false)'
INTAKE_RECEIVE = r'(?:None|Some\(\(' + ON + r', (?:None|Some\(\[' + INTAKE_FLAGS + r'\]\)), ' + ON + r', ' + N + r', ' + N + r'\)\))'
INTAKE_RECEIPT = r'(?:None|Some\(\(' + N + r', (?:true|false), ' + N + r', ' + N + r'\)\))'


def intake_dispositions(raw,ordinal,native_known,peer_proofs,required=False):
    require(type(ordinal) is int and ordinal in {4,5} and type(native_known) is bool, 'intake-frame-context')
    require(len(raw.encode()) <= 8*1024*1024, 'intake-bounded-input')
    lines = [line for line in raw.splitlines() if line.startswith('native5-intake-')]
    if not lines:
        require(not required,'intake-required-appendix-missing')
        return {'observed':False,'schema_complete':False,'known':False,'loss_mask':None,
            'snapshot_available':None,'owner_bound':None,'source_id_bound':None,'selections':None,
            'receive_gates':None,'receipt_decisions':None,'missing_reason':'MissingAppendix'}
    require(len(lines) == 94 and all(len(line.encode()) <= 4096 for line in lines), 'intake-fixed-header-fifteen-five-nine-six-five-fiftythree')
    header = re.fullmatch(r'native5-intake-meta known=(true|false) loss_mask=(' + N + r') snapshot_available=(true|false) owner_bound=(true|false) source_id_bound=\[('
        + OB + '), (' + OB + '), (' + OB + r')\] inflight_at_freeze=(' + N + ')',lines[0])
    require(header is not None,'intake-closed-header')
    known,loss,available,owner = header[1] == 'true',number(header[2],31),header[3] == 'true',header[4] == 'true'
    bindings = [boolean(header[index]) for index in range(5,8)]
    inflight=number(header[8],4294967295)
    require(known == (loss == 0 and available and inflight == 0),'intake-exact-known-lossless-snapshot')
    if available:
        require(all(type(value) is bool for value in bindings),'intake-available-bindings-known')
    else:
        require(not known and not owner and bindings == [None,None,None],'intake-unavailable-all-binding-flags-unknown')
    crosschecked = available and known and native_known
    if crosschecked:
        require(isinstance(peer_proofs,list) and len(peer_proofs) == 3,'intake-native-proofs-for-crosscheck')
        for index,proof in enumerate(peer_proofs):
            require(proof is None or (isinstance(proof,dict) and type(proof.get('first_attempt_actual_message_bound')) is bool),
                'intake-closed-native-proof-binding')
            require(bindings[index] is (False if proof is None else proof['first_attempt_actual_message_bound']),
                'intake-exact-first-proof-binding')
    selections=[]
    for index,line in enumerate(lines[1:16]):
        match=re.fullmatch(r'native5-intake-selection worker=([0-4]) channel=([0-2]) observation=('+INTAKE_SELECTION+r')',line)
        require(match is not None and (int(match[1]),int(match[2])) == (index//3,index%3),'intake-worker-major-selection-order')
        observation=None
        if match[3] != 'None':
            event=re.fullmatch(r'Some\(\(('+N+r'), ([0-3]), ('+N+r')\)\)',match[3])
            stamp,reason,later=number(event[1]),int(event[2]),number(event[3],4294967295)
            require(available and bindings[index%3] is True,'intake-selection-needs-exact-key-binding')
            require(reason != 0 or owner,'intake-matched-owner-reason-needs-owner-bound')
            observation={'selected_before_owner_filter_us':stamp,'reason':INTAKE_SELECTION_REASONS[reason],
                'later_matching_selections_not_merged':later,'actual_first_peer_key_matched':True,
                'current_owner_and_child_match_observed':reason == 0}
        selections.append({'worker_ordinal':index//3,'channel':index%3,'observation':observation})
    gates=[]
    for index,line in enumerate(lines[16:21]):
        match=re.fullmatch(r'native5-intake-gate worker=([0-4]) observation=('+INTAKE_GATE+r')',line)
        require(match is not None and int(match[1]) == index,'intake-gate-worker-order')
        observation=None
        if match[2] != 'None':
            require(available and owner,'intake-positive-owner-gate-binding')
            value=re.fullmatch(r'Some\(\(\[(.*)\], ('+N+r'), ('+N+r')\)\)',match[2])
            tokens=re.findall(INTAKE_GATE_SAMPLE,value[1]);require(', '.join(tokens) == value[1] and len(tokens) == 16,'intake-exact-sixteen-gate-slots')
            samples=[];ended=False
            for token in tokens:
                if token == 'None':ended=True;continue
                require(not ended,'intake-packed-gate-samples')
                sample=re.fullmatch(r'Some\(\(('+N+r'), (true|false)\)\)',token)
                stamp,enabled=number(sample[1]),sample[2] == 'true'
                require(not samples or (samples[-1]['observed_us'] <= stamp and samples[-1]['receive_enabled'] is not enabled),
                    'intake-monotonic-state-change-gate-samples')
                samples.append({'observed_us':stamp,'receive_enabled':enabled})
            require(bool(samples),'intake-present-gate-needs-actual-sample')
            transitions,repeated=number(value[2],4294967295),number(value[3],4294967295)
            require(transitions >= len(samples)-1,'intake-transitions-cover-stored-state-changes')
            require(transitions == len(samples)-1 or (len(samples) == 16 and loss & 4),'intake-truncated-state-changes-need-capacity-loss')
            observation={'samples':samples,'transition_count':transitions,'repeated_same_value_count':repeated,
                'positive_original_owner_bound':True,'no_new_ready_poll_or_queue_query':True}
        gates.append({'worker_ordinal':index,'observation':observation})
    receipts=[]
    for index,line in enumerate(lines[21:30]):
        match=re.fullmatch(r'native5-intake-receipt path=([0-2]) channel=([0-2]) observation=('+INTAKE_RECEIPT+r')',line)
        require(match is not None and (int(match[1]),int(match[2])) == (index//3,index%3),'intake-path-major-receipt-order')
        observation=None
        if match[3] != 'None':
            require(available and owner and bindings[index%3] is True,'intake-receipt-positive-owner-exact-key')
            value=re.fullmatch(r'Some\(\(('+N+r'), (true|false), ('+N+r'), ('+N+r')\)\)',match[3])
            observation={'existing_contains_decision_us':number(value[1]),'first_already_held':value[2] == 'true',
                'later_held_decisions':number(value[3],4294967295),'later_fresh_decisions':number(value[4],4294967295),
                'decision_is_not_Core_or_native_acceptance':True}
        receipts.append({'path':['Live','Comparison','SDKDrain'][index//3],'channel':index%3,'observation':observation})
    ingests=[]
    for index,line in enumerate(lines[30:36]):
        match=re.fullmatch(r'native5-intake-ingest path=([01]) channel=([0-2]) observation=('+INTAKE_INGEST+r')',line)
        require(match is not None and (int(match[1]),int(match[2]))==(index//3,index%3),'intake-ingest-path-major-order')
        observation=None
        if match[3]!='None':
            require(available and owner and bindings[index%3] is True,'intake-ingest-positive-original-owner-and-first-key')
            value=re.fullmatch(r'Some\(\(('+N+r'), ('+ON+r'), ('+OB+r'), ('+N+r'), ('+N+r')\)\)',match[3])
            begin,end,ok=number(value[1]),opt(value[2]),boolean(value[3])
            require((end is None)==(ok is None) and (end is None or end>=begin),'intake-ingest-actual-result-end-coherence')
            observation={'first_begin_us':begin,'first_returned_us':end,'first_result_ok':ok,
                'later_begin_count':number(value[4],4294967295),'later_end_count':number(value[5],4294967295),
                'result_does_not_establish_final_native_acceptance':True}
        ingests.append({'path':['OnceObserved','SDKDrain'][index//3],'channel':index%3,'observation':observation})
    receives=[]
    for index,line in enumerate(lines[36:41]):
        match=re.fullmatch(r'native5-intake-receive worker=([0-4]) observation=('+INTAKE_RECEIVE+r')',line)
        require(match is not None and int(match[1])==index,'intake-receive-worker-order')
        observation=None
        if match[2]!='None':
            require(available and owner,'intake-receive-positive-original-owner')
            value=re.fullmatch(r'Some\(\(('+ON+r'), (None|Some\(\[('+INTAKE_FLAGS+r')\]\)), ('+ON+r'), ('+N+r'), ('+N+r')\)\)',match[2])
            first,before=opt(value[1]),opt(value[4]);flags=None if value[2]=='None' else [v=='true' for v in value[3].split(', ')]
            require((first is None)==(flags is None) and (first is not None or before is not None),'intake-receive-initial-execution-flags-coherent')
            require(first is None or before is None or before>=first,'intake-receive-observed-order-without-attempt-coupling')
            observation={'first_async_body_execution_us':first,'initial_cached_retry_slot_present':flags,
                'first_before_actual_receive_next_delivery_us':before,'later_execution_count':number(value[5],4294967295),
                'later_before_receive_count':number(value[6],4294967295),'before_call_may_follow_later_execution':True,
                'no_new_poll_or_ready_query':True}
        receives.append({'worker_ordinal':index,'observation':observation})
    losses=[];combined_mask=0
    for index,line in enumerate(lines[41:]):
        match=re.fullmatch(r'native5-intake-loss slot=('+N+r') count=('+N+r') first_us=('+ON+r') mask=('+N+r')',line)
        require(match is not None and number(match[1],52)==index,'intake-localized-loss-slot-order')
        count,first,mask=number(match[2],4294967295),opt(match[3]),number(match[4],31)
        if inflight==0:
            require((count==0 and first is None and mask==0) or (count>0 and mask!=0 and (first is not None or mask&16)),
                'intake-quiescent-localized-loss-coherence')
        combined_mask|=mask
        losses.append({'slot':index,'count':count,'first_us':first,'mask':mask,'atomic_loss_fields_quiescent':inflight==0})
    require(combined_mask==loss,'intake-header-exact-exported-localized-loss-mask-union')
    if inflight==0:
        for index,item in enumerate(gates):
            observation=item['observation']
            if observation is not None and observation['transition_count']>len(observation['samples'])-1:
                require(losses[22+index]['mask'] & 4,'intake-truncated-gate-needs-own-capacity-loss')
    binding_loss=0
    for item in losses[:7]:binding_loss|=item['mask']
    for items,start,width in [(selections,7,1),(gates,22,1),(receipts,27,1),(ingests,36,1),(receives,42,2)]:
        for index,item in enumerate(items):
            own=losses[start+index*width:start+(index+1)*width];own_mask=0
            for entry in own:own_mask|=entry['mask']
            item['localized_loss_slots']=[entry['slot'] for entry in own]
            item['localized_loss_mask']=own_mask;item['binding_loss_mask']=binding_loss
            item['snapshot_inflight_unknown']=inflight!=0
            item['missing_observation_is_unknown']=item['observation'] is None

    return {'observed':True,'schema_complete':True,'known':known,'loss_mask':loss,'snapshot_available':available,
        'owner_bound':owner,'inflight_at_freeze':inflight,'source_id_bound':bindings,'native_first_proof_binding_crosschecked':crosschecked,
        'selections':selections,'receive_gates':gates,'receipt_decisions':receipts,'common_ingest':ingests,
        'receive_execution':receives,'localized_losses':losses,'localized_loss_slot_map':{'owner_bind':0,'recipient_bind':[1,3],'peer_bind':[4,6],
            'selection_worker_major':[7,21],'gate_worker_major':[22,26],'receipt_path_major':[27,35],
            'ingest_path_major':[36,41],'receive_worker_stage_major':[42,51],'freeze':52},
        'recipient_plane':ordinal-1,'plane_to_worker_mapping_assumed':False,
        'None_is_unknown_not_no_selection_or_no_receipt':True,'loss_is_independent_of_native_SDK_worker':True,
        'sequential_postwait_not_joint_deadline_snapshot':True,'IDs_or_payloads_exported':False}


def safe_intake_dispositions(raw,ordinal,native_known,peer_proofs):
    try:return intake_dispositions(raw,ordinal,native_known,peer_proofs)
    except ValueError:return {'observed':any(line.startswith('native5-intake-') for line in raw.splitlines()),
        'schema_complete':False,'known':False,'loss_mask':None,'snapshot_available':None,'owner_bound':None,
        'source_id_bound':None,'selections':None,'receive_gates':None,'receipt_decisions':None,
        'failure_category':'ClosedOptionalIntakeSchemaRejected','inherited_native_SDK_worker_ledger_retained':True}




def intake_fixture(known=True,loss=0,available=True,owner=True,bindings=None,selections=None,gates=None,receipts=None,ingests=None,receives=None,losses=None,inflight=0):
    bindings=bindings if bindings is not None else (['Some(true)','Some(false)','Some(true)'] if available else ['None']*3)
    rows=['native5-intake-meta known='+str(known).lower()+' loss_mask='+str(loss)+' snapshot_available='+str(available).lower()+' owner_bound='+str(owner).lower()+' source_id_bound=['+', '.join(bindings)+'] inflight_at_freeze='+str(inflight)]
    rows.extend('native5-intake-selection worker='+str(w)+' channel='+str(c)+' observation='+(selections or {}).get((w,c),'None') for w in range(5) for c in range(3))
    rows.extend('native5-intake-gate worker='+str(w)+' observation='+(gates or {}).get(w,'None') for w in range(5))
    rows.extend('native5-intake-receipt path='+str(p)+' channel='+str(c)+' observation='+(receipts or {}).get((p,c),'None') for p in range(3) for c in range(3))
    rows.extend('native5-intake-ingest path='+str(p)+' channel='+str(c)+' observation='+(ingests or {}).get((p,c),'None') for p in range(2) for c in range(3))
    rows.extend('native5-intake-receive worker='+str(w)+' observation='+(receives or {}).get(w,'None') for w in range(5))
    if losses is None:losses={52:(1,'Some(0)',loss)} if loss else {}
    for slot in range(53):
        count,first,mask=losses.get(slot,(0,'None',0))
        rows.append('native5-intake-loss slot='+str(slot)+' count='+str(count)+' first_us='+first+' mask='+str(mask))
    return '\n'.join(rows)


def intake_parser_controls():
    proofs=[{'first_attempt_actual_message_bound':True},None,{'first_attempt_actual_message_bound':True}]
    slots='[Some((0, false)), Some((1, true)), '+', '.join(['None']*14)+']'
    baseline=intake_fixture(selections={(3,0):'Some((1, 0, 0))'},gates={3:'Some(('+slots+', 1, 2))'},
        receipts={(0,0):'Some((2, false, 0, 1))',(2,0):'Some((3, true, 1, 0))'},
        ingests={(0,0):'Some((2, Some(3), Some(true), 0, 0))'},
        receives={3:'Some((Some(0), Some([false, true, false]), Some(1), 2, 1))'})
    good=[baseline,intake_fixture(),intake_fixture(False,1),intake_fixture(False,0,False,False),intake_fixture(owner=False),
        intake_fixture(selections={(0,0):'Some((600000000, 3, 4294967295))'}),
        intake_fixture(False,0,inflight=1,losses={42:(0,'Some(1)',0)}),
        intake_fixture(ingests={(1,0):'Some((0, None, None, 0, 0))'}),
        intake_fixture(receives={3:'Some((None, None, Some(1), 0, 0))'}),
        intake_fixture(False,16,losses={42:(1,'None',16)})]
    for raw in good:require(intake_dispositions(raw,4,True,proofs)['schema_complete'],'intake-positive-schema')
    independent=intake_dispositions(baseline,5,False,None)
    require(not independent['native_first_proof_binding_crosschecked'] and independent['known'],'intake-positive-independent-native-loss')
    packed='['+', '.join('Some(('+str(i)+', '+str(bool(i%2)).lower()+'))' for i in range(16))+']'
    capacity=intake_fixture(False,4,gates={0:'Some(('+packed+', 20, 0))'},losses={22:(1,'Some(0)',4)})
    require(len(intake_dispositions(capacity,4,True,proofs)['receive_gates'][0]['observation']['samples'])==16,'intake-explicit-capacity-partial-positive')
    bad=[
        '\n'.join(baseline.splitlines()[:-1]),baseline+'\n'+baseline.splitlines()[1],
        baseline.replace('worker=0 channel=0','worker=1 channel=0',1),baseline.replace('path=0 channel=0','path=1 channel=0',1),
        baseline.replace('loss_mask=0','loss_mask=32',1),baseline.replace('loss_mask=0','loss_mask=1',1),
        baseline.replace('known=true','known=false',1),baseline.replace('snapshot_available=true','snapshot_available=false',1),
        baseline.replace('source_id_bound=[Some(true)','source_id_bound=[None',1),
        baseline.replace('Some((1, 0, 0))','Some((600000001, 0, 0))'),baseline.replace('Some((1, 0, 0))','Some((1, 4, 0))'),
        baseline.replace('Some((1, 0, 0))','Some((1, 0, 4294967296))'),baseline.replace('owner_bound=true','owner_bound=false',1),
        baseline.replace('Some((0, false)), Some((1, true))','None, Some((1, true))'),
        baseline.replace('Some((0, false)), Some((1, true))','Some((2, false)), Some((1, true))'),
        baseline.replace('Some((1, true))','Some((1, false))'),baseline.replace('], 1, 2))','], 0, 2))'),baseline.replace('], 1, 2))','], 2, 2))'),
        baseline.replace('Some((2, false, 0, 1))','Some((2, false, 0, 4294967296))'),
        baseline.replace('native5-intake-gate worker=4 observation=None','native5-intake-gate worker=4 observation=PRIVATE_PAYLOAD'),
        intake_fixture(selections={(0,1):'Some((1, 1, 0))'}),intake_fixture(receipts={(1,1):'Some((1, false, 0, 0))'}),
        intake_fixture(gates={0:'Some((['+', '.join(['None']*16)+'], 0, 0))'}),capacity.replace('loss_mask=4','loss_mask=1'),
        baseline.replace('inflight_at_freeze=0','inflight_at_freeze=1'),baseline.replace('slot=52 count=0','slot=52 count=1'),
        baseline.replace('slot=0 count=0 first_us=None mask=0','slot=0 count=0 first_us=Some(0) mask=0'),
        intake_fixture(False,1,losses={0:(1,'None',1)}),intake_fixture(False,0,losses={0:(1,'Some(0)',1)}),
        baseline.replace('native5-intake-loss slot=52','native5-intake-loss slot=51'),
        baseline.replace('Some((2, Some(3), Some(true), 0, 0))','Some((2, None, Some(true), 0, 0))'),
        baseline.replace('Some((2, Some(3), Some(true), 0, 0))','Some((2, Some(1), Some(true), 0, 0))'),
        baseline.replace('Some((Some(0), Some([false, true, false])','Some((None, Some([false, true, false])'),
        baseline.replace('Some((Some(0), Some([false, true, false]), Some(1)','Some((Some(2), Some([false, true, false]), Some(1)'),
        intake_fixture(receives={0:'Some((None, None, None, 0, 0))'}),
        baseline.replace('native5-intake-ingest path=0 channel=0','native5-intake-ingest path=2 channel=0',1),
        baseline.replace('native5-intake-receive worker=0','native5-intake-receive worker=1',1),
        capacity.replace('slot=22 count=1 first_us=Some(0) mask=4','slot=22 count=0 first_us=None mask=0').replace('slot=52 count=0 first_us=None mask=0','slot=52 count=1 first_us=Some(0) mask=4'),
    ]
    for raw in bad:
        try:intake_dispositions(raw,4,True,proofs)
        except ValueError:continue
        raise ValueError('intake-adversary-accepted')
    require(not intake_dispositions('',4,True,proofs)['observed'],'intake-inherited-fixtures-optional')
    try:intake_dispositions('',4,True,proofs,required=True)
    except ValueError:pass
    else:raise ValueError('intake-current-runtime-missing-accepted')
    for mismatch in [None,[None,None,None]]:
        try:intake_dispositions(baseline,4,True,mismatch)
        except ValueError:continue
        raise ValueError('intake-native-binding-mismatch-accepted')
    safe=safe_intake_dispositions(bad[19],4,True,proofs)
    require(not safe['schema_complete'] and 'PRIVATE_PAYLOAD' not in str(safe),'intake-rejected-safe-ledger-preserved')
    return {'positive':len(good)+3,'negative':len(bad)+3,'safe_unknown_controls':1,'runtime_bodies':0,'fixtures_authored_for_remote_execution':True}


def intake_maximum_width_appendix():
    samples='['+', '.join('Some((600000000, '+str(bool(i%2)).lower()+'))' for i in range(16))+']'
    return intake_fixture(False,31,bindings=['Some(true)']*3,inflight=4294967295,
        selections={(w,c):'Some((600000000, 3, 4294967295))' for w in range(5) for c in range(3)},
        gates={w:'Some(('+samples+', 4294967295, 4294967295))' for w in range(5)},
        receipts={(p,c):'Some((600000000, false, 4294967295, 4294967295))' for p in range(3) for c in range(3)},
        ingests={(p,c):'Some((600000000, Some(600000000), Some(false), 4294967295, 4294967295))' for p in range(2) for c in range(3)},
        receives={w:'Some((Some(600000000), Some([false, false, false]), Some(600000000), 4294967295, 4294967295))' for w in range(5)},
        losses={slot:(4294967295,'Some(600000000)',31) for slot in range(53)}).splitlines()
