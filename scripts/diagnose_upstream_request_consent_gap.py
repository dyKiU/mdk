#!/usr/bin/env python3
"""One unchanged native5 body with bounded Request-to-Consent passive evidence."""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
import diagnose_upstream_post_watch_native5 as previous
frozen=previous.frozen
ensure=previous.ensure
digest=previous.digest
BASE='5ae3269f225c2cf56cce35c010409b7e44acc4f7' # Signed fixture-only existing-runtime snapshot; no source exceptions.
DIAGNOSTIC_PARENT='0b02a07916c17f8240c65f83ad2d916357c7f5fa'
SELF='scripts/diagnose_upstream_request_consent_gap.py'
WORKFLOW='.github/workflows/experimental-sync-ci.yml'
REF='refs/heads/ci/upstream-request-consent-gap-diagnostic-20261018'
BEGIN='  # REQUEST_CONSENT_GAP_JOBS_BEGIN\n'
END='  # REQUEST_CONSENT_GAP_JOBS_END\n'
OPTIONS='options: [request-consent-gap-preflight, request-consent-gap-diagnostic, '
OUT=Path('request-consent-gap-evidence')


def source_guard():
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE),'root-frozen-post-watch-diagnostic-BASE-required')
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_REQUEST_CONSENT_GAP_BASELINE')==BASE,'exact-owned-post-watch-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'unchanged-observer-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',DIAGNOSTIC_PARENT,BASE],check=True)
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-whole-HEAD-pristine')
    baseline={}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            metadata,name=item.split(b'\t',1);mode,kind,sha=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-diagnostic-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,sha)
    current=frozen.ack.layout()
    ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-post-watch-inventory-one-new-SELF')
    for path,row in current.items():
        mode,sha=baseline.get(path,('100644',None))
        ensure(row['git_mode']==mode and row['symlink']==(mode=='120000')
            and (row['symlink'] or row['actual_executable']==(mode=='100755')),'whole-post-watch-source-modes')
        data=os.fsencode(os.readlink(path)) if row['symlink'] else Path(path).read_bytes()
        if path==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-new-post-watch-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if sha is not None:ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==sha,'whole-post-watch-content-no-Rust-exceptions:'+path)
    allowed={str(OUT/'result.json'),str(OUT/'formatting.patch')}
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines())<=allowed,'no-untracked-source-overlay')
    return {'source':head,'baseline':BASE,'all_existing_source_modes_exact':True,'Rust_exceptions':[],
        'old_post_watch_wrapper_and_jobs_are_ordinary_BASE_source':True,'old_source_guards_called':False,
        'old_main_called':False,'old_module_globals_mutated':False,'runtime_evidence_reused':False}


REQUEST_STAGES=['Core_begin_before','Core_begin_returned','Request_wrap_before','Request_prepared_before_channel_validation','adapter_callsite','adapter_returned','result_received','harvest_accepted','eligible_authenticated_Request_dispatch','Core_Request_auth_returned','Core_approval_returned','recipient_ready_channel_installed']
REQUEST_OUTCOMES=['adapter_result_ok','returned_report_met_required_acks','received_result_ok','harvest_accepted','Core_Request_auth_ok','Core_approval_ok','accepted_ACK_after_existing_live_guards']

def request_gap_rows(lines,timing):
    p=frozen.timing_parser
    if not timing.get('snapshot_available'):
        ensure(not lines,'no-invented-Request-rows-without-native-snapshot')
        return {'schema_complete':True,'observed':False,'known':False,'rows':None,'missing_is_unknown':True}
    ensure(len(lines)==3 and all(len(line.encode())<=1024 for line in lines),'fixed-three-bounded-Request-rows')
    pattern=r'native5-request index=([012]) observation=(?:None|Some\(\(\['+', '.join(['('+p.ON+')']*12)+r'\], \['+', '.join(['('+p.OB+')']*7)+r'\], ('+p.N+r'), ('+p.N+r'), (true|false), (None|Some\([012]\))\)\))'
    rows=[];linked=[]
    for index,line in enumerate(lines):
        m=re.fullmatch(pattern,line);ensure(m is not None and int(m[1])==index,'closed-Request-row-and-index')
        if line.endswith('observation=None'):rows.append(None);continue
        times=[p.opt(m[j]) for j in range(2,14)]
        outcomes=[p.boolean(m[j]) for j in range(14,21)]
        later=p.number(m[21],4294967295);dispatches=p.number(m[22],4294967295)
        installed=m[23]=='true';slot=p.opt(m[24],2)
        if timing.get('known') is True:
            ensure(p.ordered_observed(times[:8]) and p.ordered_observed(times[8:]),'Request-source-and-first-receive-partial-orders')
            ensure(all(value is None or times[event] is not None for value,event in zip(outcomes[:6],[5,5,6,7,9,10])),'Request-outcome-requires-actual-result')
            ensure(outcomes[1] is None or outcomes[0] is True,'Request-met-ACK-flag-requires-actual-Ok-report')
            ensure(outcomes[6] is None or outcomes[6] is True and outcomes[0] is True and outcomes[1] is True,'Request-accepted-ACK-is-actual-true-after-successful-report')
            ensure(times[7] is None or outcomes[2] is True and outcomes[3] is True,'Request-harvest-requires-actual-successful-receive')
            ensure(not installed or times[11] is not None and outcomes[4] is True and outcomes[5] is True,'Request-installed-requires-real-Core-results')
            ensure(times[11] is None or installed,'Request-installed-time-requires-owned-installed-channel')
        ensure(slot is None or installed,'Request-Consent-link-needs-authenticated-installed-channel')
        if slot is not None:
            slots=timing.get('slots')
            ensure(isinstance(slots,list) and len(slots)==3 and slots[slot] is not None,'Request-link-needs-actual-Consent-slot')
            if timing.get('known') is True:
                prepared=slots[slot]['milestone_us']['prepared']
                ensure(times[11] is not None and prepared is not None and times[11]<=prepared,'Request-installed-before-linked-Consent-preparation')
            linked.append(slot)
        wait=timing.get('wait') or {};lo=wait.get('deadline_lower_us');hi=wait.get('deadline_upper_us')
        rows.append({'request_record_ordinal':index,'stage_us':dict(zip(REQUEST_STAGES,times)),
            'deadline_relation':dict(zip(REQUEST_STAGES,[p.relation(value,lo,hi) for value in times])),
            'actual_outcomes':dict(zip(REQUEST_OUTCOMES,outcomes)),'later_source_attempts':later,'later_receive_dispatches':dispatches,
            'authenticated_recipient_channel_installed':installed,'linked_Consent_slot':slot,
            'exact_recipient_owner_correlated_at_install':installed,'current_context_liveness_at_freeze':None,'live_context_checked_at_Consent_link':slot is not None,'unlinked_source_candidate_is_not_an_owned_peer_claim':True,
            'earliest_receive_point_is_authenticated_control_dispatch_not_network_decode':True,
            'Request_has_no_new_SDK_stage_or_message_identity_ledger':True,'logical_channel_link_does_not_prove_first_outer_event_delivery':True,'first_source_attempt_and_first_recipient_dispatch_are_separate':True})
    ensure(len(linked)==len(set(linked)),'unique-Request-to-Consent-slot-link')
    return {'schema_complete':True,'observed':True,'known':timing.get('known') is True,'rows':rows,
        'missing_is_unknown':True,'unlinked_candidates_remain_unknown_for_recipient_owner':True,
        'first_contiguous_receive_attempt_not_filled_by_later_retries':True,'physical_SDK_entry_not_observed':True}


def request_gap_windows(raw,name,windows):
    p=frozen.timing_parser
    ensure(len(raw.encode())<=8*1024*1024,'bounded-Request-window-input')
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    raw,prefix=re.subn(r'(?m)^test '+re.escape(name)+r' \.\.\. (?=native5-join-window begin ordinal=)','',raw)
    ensure(prefix<=1 and not re.search(r'(?m)^test [A-Za-z0-9_:]+ \.\.\. native5-join-window',raw),'exact-Request-shared-test-prefix')
    ensure(not re.search(r'(?m)^test [A-Za-z0-9_:]+ \.\.\. native5-runtime',raw),'foreign-runtime-prefix')
    frames=[];active=None;lines=[];prefix_lines=[];runtime_lines=[]
    for line in raw.splitlines():
        if line.startswith('native5-join-window'):
            m=re.fullmatch(r'native5-join-window (begin|end) ordinal=([45])',line);ensure(m is not None,'closed-Request-window-marker')
            ordinal=int(m[2])
            if m[1]=='begin':
                ensure(active is None and ordinal==4+len(frames) and len(frames)<2,'ordered-Request-window-begin');active=ordinal;lines=[];prefix_lines=[];runtime_lines=[]
            else:
                ensure(active==ordinal and len(windows['windows'])>len(frames),'matching-Request-window-end')
                original=windows['windows'][len(frames)]
                ensure(original['actual_join_ordinal']==ordinal,'same-original-native-window')
                frames.append({'actual_join_ordinal':ordinal,'request_gap':request_gap_rows(lines,original['timing']),'prefix_summary':prefix_summary(prefix_lines,ordinal,original['timing'],original.get('notification_dispositions')),'runtime_summary':runtime_summary(runtime_lines)});active=None
        elif line.startswith('native5-runtime'):
            ensure(active is not None,'no-orphan-runtime-summary');runtime_lines.append(line)
        elif line.startswith('native5-prefix'):
            ensure(active is not None,'no-orphan-prefix-rows');prefix_lines.append(line)
        elif line.startswith('native5-request'):
            ensure(active is not None,'no-orphan-Request-rows');lines.append(line)
    ensure(active is None and len(frames)==len(windows['windows']),'all-original-Request-windows-closed')
    return {'windows':frames,'exact_test_prefix_normalizations':prefix,'schema_complete':all(frame['request_gap']['schema_complete'] for frame in frames),
        'diagnostic_only':True,'source_candidate_without_full_link_is_not_exact_owner_evidence':True}


def request_parser_controls():
    p=frozen.timing_parser
    empty=['native5-request index='+str(i)+' observation=None' for i in range(3)]
    context={'snapshot_available':True,'known':True,'slots':[None]*3,'wait':{}}
    request_gap_rows(empty,context)
    some='native5-request index=0 observation=Some((['+', '.join('Some('+str(i)+')' for i in range(12))+'], ['+', '.join(['Some(true)']*7)+'], 1, 2, true, Some(0)))'
    context['slots'][0]={'milestone_us':{'prepared':12}}
    valid=[some,*empty[1:]];request_gap_rows(valid,context)
    unlinked=some.replace('true, Some(0)))','false, None))').replace('Some(11)]','None]')
    request_gap_rows([unlinked,*empty[1:]],context)
    request_gap_rows([],{'snapshot_available':False,'known':False})
    name='closed::actual_native5'
    frame='native5-join-window begin ordinal=4\n'+'\n'.join(valid)+'\nnative5-join-window end ordinal=4'
    windows={'windows':[{'actual_join_ordinal':4,'timing':context}]}
    request_gap_windows('test '+name+' ... '+frame,name,windows)
    bad=[valid+[empty[2]],list(reversed(valid)),[some+' PRIVATE',*empty[1:]],
        [some.replace('index=0','index=true'),*empty[1:]],
        [some.replace('Some(0), Some(1)','Some(2), Some(1)'),*empty[1:]],
        [some.replace('Some(11)]','None]'),*empty[1:]],
        [some.replace('true, Some(0)))','false, Some(0)))'),*empty[1:]],
        [some.replace('Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)','Some(false), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)'),*empty[1:]],
        [some.replace('Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)','Some(false), Some(true), Some(true), Some(true), Some(true), Some(true), None'),*empty[1:]],
        [some.replace('Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(true)','Some(true), Some(true), Some(true), Some(true), Some(true), Some(true), Some(false)'),*empty[1:]],
        [some.replace(', 1, 2, true',', true, 2, true'),*empty[1:]],
        [some.replace('Some(11)]','Some(600000001)]'),*empty[1:]],
        [some,some.replace('index=0','index=1'),empty[2]]]
    for value in bad:
        rejected=False
        try:request_gap_rows(value,context)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'Request-invalid-closed-row-rejected')
    prefix_bad=['test foreign::case ... '+frame,frame+'\n'+empty[0],frame.replace('end ordinal=4','end ordinal=5'),frame.replace('ordinal=4','ordinal=3')]
    for value in prefix_bad:
        rejected=False
        try:request_gap_windows(value,name,windows)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'Request-invalid-prefix-or-frame-rejected')
    # Worst-case source serialization shape only; no runtime evidence invented.
    maximum='native5-request index=0 observation=Some((['+', '.join(['Some(600000000)']*12)+'], ['+', '.join(['Some(false)']*7)+'], 4294967295, 4294967295, false, Some(2)))'
    extra_bytes=len(('\n'.join(maximum.replace('index=0','index='+str(i)) for i in range(3))+'\n').encode())
    existing=p.worker_output_capacity_control()
    ensure(existing['maximum_width_serialized_bytes']+extra_bytes<=65536,'unchanged-64KiB-whole-window-with-Request-rows')
    return {'positive':5,'negative':len(bad)+len(prefix_bad),'runtime_bodies':0,
        'existing_maximum_width_bytes':existing['maximum_width_serialized_bytes'],'Request_maximum_extra_bytes':extra_bytes,
        'combined_maximum_width_bytes':existing['maximum_width_serialized_bytes']+extra_bytes,'cap_bytes':65536,
        'capacity_fixture_is_not_runtime_evidence':True}


# Existing-map summaries only, not an exhaustive receive trace or FIFO proof.
def prefix_summary(lines,ordinal,timing,notification):
    p=frozen.timing_parser
    if not lines:return {'observed':False,'schema_complete':False,'map_available':None,'rows':None,'missing_is_unknown':True}
    ensure(len(lines)<=4 and all(len(line.encode())<=512 for line in lines),'bounded-prefix-summary')
    m=re.fullmatch(r'native5-prefix observed=(true|false) entries=('+p.ON+r') at_capacity=('+p.OB+r')',lines[0]);ensure(m is not None,'closed-prefix-header')
    observed=m[1]=='true';entries=p.opt(m[2],512);atcap=p.boolean(m[3])
    if not observed:
        ensure(len(lines)==1 and entries is None and atcap is None,'unavailable-prefix-map-is-unknown')
        return {'observed':True,'schema_complete':True,'map_available':False,'entries':None,'at_capacity':None,'rows':None,'missing_is_unknown':True}
    ensure(len(lines)==4 and entries is not None and type(atcap) is bool and atcap==(entries==512),'exact-prefix-map-capacity-state')
    u64=r'(?:0|[1-9][0-9]{0,19})'
    pattern=r'native5-prefix-row index=([012]) observation=(?:None|Some\(\(('+p.ON+r'), ('+p.N+r'), ('+u64+r'), ('+p.N+r'), ('+p.N+r'), ('+p.ON+r'), ('+p.ON+r'), (true|false)\)\))'
    rows=[]
    for index,line in enumerate(lines[1:]):
        m=re.fullmatch(pattern,line);ensure(m is not None and int(m[1])==index,'closed-three-prefix-row-indices')
        if line.endswith('observation=None'):rows.append(None);continue
        anchor=p.opt(m[2]);distinct=p.number(m[3],512);callbacks=int(m[4]);pending=p.number(m[5],512);excluded=p.number(m[6],512)
        first=p.opt(m[7]);last=p.opt(m[8]);invalid=m[9]=='true'
        ensure(callbacks<=18446744073709551615 and entries>=1 and distinct+pending+excluded<=entries-1,'prefix-count-bounds-and-observed-record-partition')
        ensure(anchor is not None or invalid,'prefix-clock-miss-remains-invalid')
        if distinct==0:ensure(callbacks==0 and first is None and last is None,'no-invented-positive-prefix-callbacks')
        elif not invalid:
            ensure(callbacks>=distinct and first is not None and last is not None and anchor is not None and anchor<=first<=last,'positive-prefix-callback-lower-bound-and-times')
        ensure(timing.get('snapshot_available') is True,'prefix-row-requires-native-ID-snapshot')
        bound=(notification or {}).get('source_id_bound')
        if (notification or {}).get('schema_complete') is True and isinstance(bound,list):
            ensure(len(bound)==3 and bound[index] is True,'prefix-row-needs-same-freeze-bound-first-peer-ID')
        proofs=timing.get('peer_proofs')
        if timing.get('known') is True:
            ensure(isinstance(proofs,list) and len(proofs)==3 and proofs[index] is not None and proofs[index]['first_attempt_actual_message_bound'] is True,'prefix-needs-actual-first-peer-key')
        # Independent getters; only compare the immutable first-placement time
        # when both captured it. Do not assert a joint snapshot or stage order.
        for prior in (notification or {}).get('rows') or []:
            if prior.get('plane')==ordinal-1 and prior.get('channel')==index:
                captured=(prior.get('placement_first_dispatcher_us') or {}).get('queue_accepted')
                if captured is not None and anchor is not None:ensure(captured==anchor,'same-immutable-prefix-target-first-placement')
        rows.append({'channel_index':index,'target_first_QueueAccepted_us':anchor,'older_record_distinct_first_dequeued_at_or_after_anchor':distinct,
            'their_observed_Delivery_dequeue_callback_sum':callbacks,'older_accepted_records_without_observed_dequeue':pending,
            'older_records_first_dequeued_before_anchor':excluded,'earliest_qualifying_FIRST_dequeue_us':first,'latest_qualifying_FIRST_dequeue_us':last,
            'invalid_observation':invalid,'lower_bounds_only':True,'old_first_before_anchor_later_repeats_unknown':True})
    return {'observed':True,'schema_complete':True,'map_available':True,'entries':entries,'at_capacity':atcap,'capacity_may_have_excluded_new_ids':atcap,'not_complete_queue_history':True,'complete_protocol_or_network_coverage':False,
        'rows':rows,'recipient_plane':ordinal-1,'native_ledger_known':timing.get('known') is True,'native_first_peer_key_crosschecked':timing.get('known') is True,'Delivery_subset_Overflow_excluded':True,'new_hotpath_or_ledger':False,
        'callback_mutex_order_is_not_exact_removal_or_FIFO_position':True,'first_accepted_and_dequeue_clock_are_observer_callbacks':True,
        'no_joint_snapshot_with_old_getters_or_native':True,'missing_target_or_anchor_remains_unknown':True,
        'all_after_anchor_count_is_lower_bound_not_complete_prefix_total':True}


def prefix_parser_controls():
    empty=['native5-prefix observed=true entries=Some(3) at_capacity=Some(false)']+['native5-prefix-row index='+str(i)+' observation=None' for i in range(3)]
    context={'known':True,'snapshot_available':True,'peer_proofs':[{'first_attempt_actual_message_bound':True},None,None]}
    prefix_summary(empty,4,context,{})
    some='native5-prefix-row index=0 observation=Some((Some(10), 1, 2, 1, 0, Some(11), Some(12), false))'
    valid=[empty[0],some,*empty[2:]];prefix_summary(valid,4,context,{})
    prefix_summary(['native5-prefix observed=false entries=None at_capacity=None'],4,context,{})
    prefix_summary([line.replace('entries=Some(3) at_capacity=Some(false)','entries=Some(512) at_capacity=Some(true)') for line in valid],4,context,{})
    partial=[valid[0],some.replace('Some(11), Some(12), false','None, None, true'),*empty[2:]];prefix_summary(partial,4,context,{})
    prefix_summary(valid,4,dict(context,known=False),{'schema_complete':True,'source_id_bound':[True,False,False]})
    bad=[valid+[empty[-1]],valid[:-1],list(reversed(valid)),[valid[0],some+' PRIVATE',*empty[2:]],
        [line.replace('at_capacity=Some(false)','at_capacity=Some(true)') for line in valid],
        [line.replace('entries=Some(3)','entries=Some(513)') for line in valid],
        [valid[0],some.replace(', 1, 2, 1, 0,',', true, 2, 1, 0,'),*empty[2:]],
        [valid[0],some.replace(', 1, 2, 1, 0,',', 2, 2, 1, 0,'),*empty[2:]],
        [valid[0],some.replace(', 1, 2, 1, 0,',', 1, 18446744073709551616, 1, 0,'),*empty[2:]],
        [valid[0],some.replace('Some(11), Some(12)','Some(9), Some(12)'),*empty[2:]],
        [valid[0],some.replace('Some(11), Some(12)','None, None'),*empty[2:]],
        [valid[0],some.replace('Some(10)','None'),*empty[2:]],
        ['native5-prefix observed=false entries=None at_capacity=None',*empty[1:]]]
    for value in bad:
        rejected=False
        try:prefix_summary(value,4,context,{})
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'invalid-prefix-closed-shape-rejected')
    for ctx,prior in [({'known':True,'snapshot_available':True,'peer_proofs':[None]*3},{}),(context,{'rows':[{'plane':3,'channel':0,'placement_first_dispatcher_us':{'queue_accepted':9}}]})]:
        rejected=False
        try:prefix_summary(valid,4,ctx,prior)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'invalid-prefix-source-binding-rejected')
    frame_context=dict(context,snapshot_available=True,slots=[None]*3,wait={})
    frame='native5-join-window begin ordinal=4\n'+'\n'.join('native5-request index='+str(i)+' observation=None' for i in range(3))+'\n'+'\n'.join(valid)+'\nnative5-join-window end ordinal=4'
    frames={'windows':[{'actual_join_ordinal':4,'timing':frame_context}]}
    request_gap_windows(frame,'closed::case',frames)
    for value in [valid[1]+'\n'+frame,frame+'\n'+valid[0],'test foreign::case ... '+frame]:
        rejected=False
        try:request_gap_windows(value,'closed::case',frames)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'prefix-orphan-or-foreign-test-frame-rejected')
    for ctx,prior in [(dict(context,known=False,snapshot_available=False),{}),(context,{'schema_complete':True,'source_id_bound':[False,False,False]})]:
        rejected=False
        try:prefix_summary(valid,4,ctx,prior)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'prefix-impossible-snapshot-or-key-binding-rejected')
    maximum=['native5-prefix observed=true entries=Some(512) at_capacity=Some(false)']
    maximum+=['native5-prefix-row index='+str(i)+' observation=Some((Some(600000000), 512, 18446744073709551615, 512, 512, Some(600000000), Some(600000000), false))' for i in range(3)]
    extra=len(('\n'.join(maximum)+'\n').encode())
    old=request_parser_controls()['combined_maximum_width_bytes']
    ensure(old+extra<=65536 and all(len(line.encode())<=512 for line in maximum),'unchanged-whole-window-cap-with-prefix-summary')
    return {'positive':7,'negative':len(bad)+7,'runtime_bodies':0,'prefix_maximum_bytes':extra,
        'combined_maximum_width_bytes':old+extra,'cap_bytes':65536,'capacity_fixture_is_not_runtime_evidence':True}


RUNTIME_OPS=['WorkerReceive','Ingest','WorkerMaintenance','IngestEngine']
RUNTIME_FIELDS=['started','completed','in_flight','completed_wall_sum_ms','oldest_tracked_in_flight_ms','untracked_in_flight']

def runtime_summary(lines):
    if not lines:return {'observed':False,'schema_complete':False,'missing_is_unknown':True}
    ensure(len(lines)==1 and len(lines[0].encode())<=715,'one-bounded-runtime-summary')
    n=r'(?:0|[1-9][0-9]{0,19})'
    def array(count):return r'(?:None|Some\(\['+n+(r', '+n)*(count-1)+r'\]\))'
    pattern=r'native5-runtime observation=\(\[('+array(6)+r'), ('+array(6)+r'), ('+array(6)+r'), ('+array(6)+r')\], ('+array(3)+r')\)'
    m=re.fullmatch(pattern,lines[0]);ensure(m is not None,'closed-runtime-summary')
    def values(text,count):
        if text=='None':return None
        result=[int(v) for v in text[6:-2].split(', ')]
        ensure(len(result)==count and all(0<=v<=18446744073709551615 for v in result),'runtime-u64-bounds')
        return result
    rows=[values(m[j],6) for j in range(1,5)];projection=values(m[5],3)
    # No arithmetic equality across independently sampled atomics/operations.
    return {'observed':True,'schema_complete':True,'operations':dict(zip(RUNTIME_OPS,[None if row is None else dict(zip(RUNTIME_FIELDS,row)) for row in rows])),
        'inbound_delivery_projection':None if projection is None else dict(zip(['attempts','failures','completed_wall_sum_ms'],projection)),
        'scope':'selected recipient RuntimeShared; all its accounts; cumulative since runtime creation',
        'not_join_or_deadline_scoped':True,'snapshots_are_not_joint_atomic':True,'durations_are_wall_not_CPU':True,
        'Core_phase_completed_only_zero_active_cannot_exclude_work':True,'WorkerReceive_ends_before_later_history_tail':True,
        'oldest_age_zero_may_mean_no_tracked_start_or_submillisecond':True,'missing_operation_is_unknown_not_zero':True}

def runtime_parser_controls():
    zero='Some([0, 0, 0, 0, 0, 0])';proj='Some([0, 0, 0])'
    def line(ops,projection):return 'native5-runtime observation=(['+', '.join(ops)+'], '+projection+')'
    good=[line([zero]*4,proj),line(['None',zero,'None',zero],proj),line(['None']*4,'None'),line(['Some([10, 3, 7, 4, 9, 1])']*4,proj)]
    for value in good:runtime_summary([value])
    ensure(runtime_summary([])['schema_complete'] is False,'missing-runtime-summary-not-invented')
    bad=[[good[0],good[0]],[good[0]+' PRIVATE'],[good[0].replace('native5-runtime','foreign-runtime')],
        [good[0].replace('[0, 0, 0, 0, 0, 0]','[true, 0, 0, 0, 0, 0]',1)],
        [good[0].replace('[0, 0, 0, 0, 0, 0]','[-1, 0, 0, 0, 0, 0]',1)],
        [good[0].replace('[0, 0, 0, 0, 0, 0]','[18446744073709551616, 0, 0, 0, 0, 0]',1)],
        [good[0].replace('[0, 0, 0, 0, 0, 0]','[00, 0, 0, 0, 0, 0]',1)],
        [line([zero]*3,proj)],[line([zero]*5,proj)],[line([zero]*4,'Some([0, 0])')],
        [good[0].replace('None','false')+'\n'],['native5-runtime observation=None']]
    for value in bad:
        rejected=False
        try:runtime_summary(value)
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'runtime-invalid-closed-row-rejected')
    maximum=line(['Some(['+', '.join(['18446744073709551615']*6)+'])']*4,'Some(['+', '.join(['18446744073709551615']*3)+'])')
    runtime_summary([maximum]);extra=len((maximum+'\n').encode());old=prefix_parser_controls()['combined_maximum_width_bytes']
    ensure(extra<=715 and old+extra<=65536,'unchanged-whole-window-cap-with-runtime-summary')
    # Collector must reject orphan and foreign-prefixed rows before raw data is discarded.
    for raw in [good[0],'test foreign::case ... '+good[0]]:
        rejected=False
        try:request_gap_windows(raw,'closed::case',{'windows':[]})
        except (ValueError,frozen.bounded.GateFailure):rejected=True
        ensure(rejected,'orphan-runtime-summary-rejected')
    return {'positive':len(good),'negative':len(bad)+2,'missing_unknown':1,'runtime_bodies':0,
        'runtime_maximum_bytes':extra,'combined_maximum_width_bytes':old+extra,'cap_bytes':65536,
        'capacity_fixture_is_not_runtime_evidence':True}


def controls():
    return {'legacy':previous.controls(),'Request_gap':request_parser_controls(),'prefix':prefix_parser_controls(),'runtime_summary':runtime_parser_controls(),'worker':frozen.timing_parser.worker_parser_controls()} # Data/parsers only; no legacy guard or main.


def compile_one(report,save):
    return previous.compile_one(report,save) # Guard-free exact one-case compile/inventory helper.


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'baseline':BASE,'scope':'one-original-request-consent-gap-passive-diagnostic','qualification_passed':False,
        'native_qualification':False,'promotion_eligible':False,'runtime_execution_attempted':False,
        'actual_counts_complete':False,'actual_passed':None,'actual_failed':None,'actual_ignored':None,
        'actual_executed_nonignored':None,'actual_native5_pass':False,'diagnostic_completed':False,'automatic_retries':0,
        'source_composition':{'post_watch_diagnostic_parent':DIAGNOSTIC_PARENT,'command_offer_retained':True,
            'experimental_watch_offer_retained':True,'passive_Request_gap_added':True,'all_existing_passive_observations_retained':True,
            'final_pure_source_closure_equal':False,'current_pure_owner_and_test_support_not_same_whole_tree':True},
        'interpretation':{'worker_selected_masks':{'9':'completion service','17':'claimed delivery ingest','65':'command'},
            'mixed_mask_not_exclusive_arm_attribution':True,'poll_and_stage_durations_are_wall_not_CPU':True,
            'suspended_gap_not_proven_ready_queue_residence':True,'native_ACK_to_same_sealed_wire_route_focus':True,
            'first_outer_delivery_is_separate_identity_observation':True}}

    before=None;binary=None;binary_sha=None
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard();report['parser_controls']=controls();save()
        if args.preflight:
            code,raw,seconds=frozen.bounded.capture(['cargo','fmt','--all'],180,limit=8*1024*1024)
            patch=subprocess.check_output(['git','diff','--binary'])
            report['format']={'exit_code':code,'seconds':seconds,'patch_bytes':len(patch),'patch_sha256':digest(patch)}
            if patch:(OUT/'formatting.patch').write_bytes(patch)
            save();ensure(code==0 and not patch,'hosted-format-required');report['preflight_passed']=True;save();return
        before=frozen.frozen_inputs();report['source_before_sha256']=digest(json.dumps(before,sort_keys=True).encode())
        case=compile_one(report,save);binary=Path(case['binary']);binary_sha=case['binary_sha256']
        report['binary_before_sha256']=binary_sha
        ensure(frozen.frozen_inputs()==before and binary.is_file() and digest(binary.read_bytes())==binary_sha,'before-body-source-binary-pristine')
        report['runtime_execution_attempted']=True;save()
        code,raw,seconds=frozen.bounded.capture([str(binary),'--exact',frozen.NAME,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
        row=frozen.counts.parse_body(raw,code,frozen.NAME)
        report['body']=row;report['body_seconds']=seconds;report['body_exit_code']=code
        report['actual_counts_complete']=row.get('actual_counts_complete') is True
        for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:report[dest]=row.get(key)
        report['source_after_body_sha256']=digest(json.dumps(frozen.frozen_inputs(),sort_keys=True).encode())
        report['inputs_after_body_pristine']=frozen.frozen_inputs()==before
        report['binary_after_body_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
        report['binary_after_body_pristine']=report['binary_after_body_sha256']==binary_sha;save()
        report['body']=frozen.parse(raw,code);report['actual_native5_pass']=frozen.green(report['body'])
        report['panic_observations']=frozen.safe_panic_locations(raw,before);save()
        if code!=0:
            report['closed_failure_observations']=frozen.closed_failure_observations(raw,(report['body'].get('facts') or {}).get('completed_steps'));save()
        report['timing_windows']=frozen.timing_parser.timing_windows(raw,frozen.NAME);save()
        report['Request_gap_windows']=request_gap_windows(raw,frozen.NAME,report['timing_windows']);save()
        windows=report['timing_windows']['windows']
        def known_window(window):
            timing=window['timing'];wait=timing.get('wait')
            return (timing['known'] is True and isinstance(wait,dict)
                and all(type(wait.get(k)) is int for k in ['constructed_before_us','constructed_after_us','observed_us'])
                and type(wait.get('outcome_ok')) is bool)
        report['native_windows_completed']=bool(windows) and all(known_window(w) for w in windows)
        report['notification_schemas_complete']=bool(windows) and all(w['notification_dispositions'].get('observed') is True and w['notification_dispositions'].get('schema_complete') is True for w in windows)
        report['intake_schemas_complete']=bool(windows) and all(w['intake_dispositions'].get('observed') is True and w['intake_dispositions'].get('schema_complete') is True for w in windows)
        report['actual_named_body_observed']=(row.get('actual_counts_complete') is True
            and all(type(row.get(k)) is int and row[k]==v for k,v in {'executed_nonignored':1,'ignored':0,'compiler_error_count':0}.items())
            and type(code) is int and code in {0,101})
        report['diagnostic_completed']=all(report[k] is True for k in ['actual_named_body_observed','native_windows_completed','notification_schemas_complete','intake_schemas_complete'])
        report['SDK_worker_intake_known_are_independent']=True
        report['Request_gap_schema_complete']=report['Request_gap_windows']['schema_complete']
        report['prefix_schemas_complete']=bool(report['Request_gap_windows']['windows']) and all(w['prefix_summary']['schema_complete'] for w in report['Request_gap_windows']['windows'])
        report['diagnostic_completed']=report['diagnostic_completed'] and report['prefix_schemas_complete']
        report['runtime_summary_schemas_complete']=bool(report['Request_gap_windows']['windows']) and all(w['runtime_summary']['schema_complete'] for w in report['Request_gap_windows']['windows'])
        report['diagnostic_completed']=report['diagnostic_completed'] and report['runtime_summary_schemas_complete']
        report['Request_candidate_owner_requires_actual_authenticated_channel_link']=True
        report['missing_fifth_is_not_zero_or_pass']=True
        report['plane_shutdown_semantics']='returned shutdown calls; internal task quiescence not established';save()
        ensure(row['actual_counts_complete'] is True and type(row.get('executed_nonignored')) is int and row['executed_nonignored']==1
            and type(row.get('ignored')) is int and row['ignored']==0 and type(row.get('compiler_error_count')) is int and row['compiler_error_count']==0,'one-actual-native5-body-required')
        ensure(report['inputs_after_body_pristine'] and report['binary_after_body_pristine'],'after-body-source-binary-pristine')
        ensure(report['diagnostic_completed'],'closed-known-native-windows-and-supplemental-schemas-required')
        ensure(report['Request_gap_schema_complete'],'closed-Request-gap-rows-required')
        ensure(report['prefix_schemas_complete'],'closed-prefix-summary-required')
        ensure(report['runtime_summary_schemas_complete'],'closed-runtime-summary-required')
    except frozen.bounded.GateFailure as error:
        report['watchdog_triggered']=str(error)=='bounded-command-timeout';report['output_limit_triggered']=str(error)=='bounded-command-output-limit'
        report['exception_type']=type(error).__name__
        if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)):report['failure_gate']=str(error)
        save();raise
    except Exception as error:
        report['exception_type']=type(error).__name__
        if isinstance(error,ValueError):report['failure_gate']=str(error) if re.fullmatch('[A-Za-z0-9_.:/-]{1,140}',str(error)) else 'closed-gate-rejected'
        save();raise
    finally:
        if before is not None:
            report['inputs_pristine']=frozen.frozen_inputs()==before
            report['source_final_sha256']=digest(json.dumps(frozen.frozen_inputs(),sort_keys=True).encode())
            if not report['runtime_execution_attempted']:report['actual_executed_nonignored']=0
        if binary is not None:
            report['binary_final_sha256']=digest(binary.read_bytes()) if binary.is_file() else None
            report['binary_pristine']=report['binary_final_sha256']==binary_sha
        if report.get('inputs_pristine') is False or report.get('binary_pristine') is False:
            report['observed_native5_pass']=report['actual_native5_pass'];report['actual_native5_pass']=False;report['diagnostic_completed']=False
        save()
        if before is not None:ensure(report['inputs_pristine'],'final-source-modes-pristine')
        if binary is not None:ensure(report['binary_pristine'],'final-binary-pristine')

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--preflight',action='store_true');main(ap.parse_args())
