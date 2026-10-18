# DRAFT parser additions for the reviewed stress0 adapter; never run locally.
import re

MILESTONES = ['prepared', 'validated', 'task_poll', 'adapter_callsite', 'adapter_returned',
              'accepted_ack', 'result_send', 'result_receive', 'harvest_success']
OUTCOMES = ['adapter_result_ok', 'returned_report_met_required_acks', 'result_send_accepted',
            'received_result_ok', 'harvest_accepted']
NUM = r'(?:0|[1-9][0-9]{0,9})'
OPTNUM = r'(?:None|Some\(' + NUM + r'\))'
OPTBOOL = r'(?:None|Some\((?:true|false)\))'


def require(value, label):
    if not value: raise ValueError(label)


def optional_number(value, maximum):
    if value == 'None': return None
    require(re.fullmatch(r'Some\(' + NUM + r'\)', value) is not None, 'closed-option-number')
    result = int(value[5:-1]); require(result <= maximum, 'bounded-option-number'); return result


def optional_bool(value):
    require(value in {'None','Some(true)','Some(false)'}, 'closed-option-boolean')
    return None if value == 'None' else value == 'Some(true)'


def parse_consent_timing(raw):
    require(len(raw.encode()) <= 8*1024*1024, 'bounded-timing-output')
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    lines = [line for line in clean.splitlines() if line.startswith('stress0-consent-')]
    require(1 <= len(lines) <= 4 and all(len(line) < 4096 for line in lines), 'bounded-timing-lines')
    header = re.fullmatch(r'stress0-consent-timing known=(true|false) loss_mask=('+NUM+r') snapshot_available=(true|false)', lines[0])
    require(header is not None, 'one-closed-timing-header')
    known, loss, available = header[1]=='true', int(header[2]), header[3]=='true'
    require(loss <= 127 and known == (loss == 0) and (available or not known), 'closed-loss-mask-and-unknown-semantics')
    result = {'known':known,'loss_mask':loss,'snapshot_available':available,
              'exact_deadline_known':False,'wait':None,'slots':None,
              'all_milestones_observed':False,'diagnostic_only':True,
              'adapter_callsite_is_not_physical_network_entry':True,
              'missing_milestones_are_not_zero_or_negative_proof':True}
    if not available:
        require(len(lines)==1, 'unavailable-snapshot-no-invented-matrix'); return result
    require(len(lines)==4, 'one-wait-two-fixed-slots')
    wait = re.fullmatch(r'stress0-consent-wait constructed_before_us=('+OPTNUM+r') constructed_after_us=('+OPTNUM+r') deadline_lower_us=('+OPTNUM+r') deadline_upper_us=('+OPTNUM+r') outcome_ok=('+OPTBOOL+r') observed_us=('+OPTNUM+r') exact_deadline_known=false', lines[1])
    require(wait is not None, 'closed-construction-bounds-and-observation')
    before,after,lower,upper = [optional_number(wait[i],615_000_000) for i in range(1,5)]
    outcome = optional_bool(wait[5]); observed = optional_number(wait[6],600_000_000)
    require(lower == (None if before is None else before+15_000_000)
            and upper == (None if after is None else after+15_000_000)
            and (before is None or after is None or before<=after), 'exact-original-duration-bounds')
    result['wait'] = dict(constructed_before_us=before,constructed_after_us=after,
        deadline_lower_us=lower,deadline_upper_us=upper,outcome_ok=outcome,observed_us=observed)
    rows=[]
    slot_pattern = r'stress0-consent-slot index=([01]) observation=(?:None|Some\(\(\[' + ', '.join(['('+OPTNUM+')']*9) + r'\], \[' + ', '.join(['('+OPTBOOL+')']*5) + r'\], ('+NUM+r')\)\))'
    for index,line in enumerate(lines[2:]):
        match=re.fullmatch(slot_pattern,line)
        require(match is not None and int(match[1])==index, 'two-unique-ordered-closed-slots')
        if line.endswith('observation=None'):
            rows.append(None); continue
        values=match.groups()[1:]
        times=[optional_number(value,600_000_000) for value in values[:9]]
        flags=[optional_bool(value) for value in values[9:14]]
        retries=int(values[14]);require(retries<=4_294_967_295,'bounded-saturating-retry-counter')
        rows.append({'milestone_us':dict(zip(MILESTONES,times)),
                     'outcomes':dict(zip(OUTCOMES,flags)),'subsequent_prepared_attempts':retries})
    result['slots']=rows
    result['all_milestones_observed'] = known and all(row is not None and all(value is not None for value in row['milestone_us'].values()) for row in rows)
    return result


def timing_parser_controls():
    header='stress0-consent-timing known=true loss_mask=0 snapshot_available=true'
    wait='stress0-consent-wait constructed_before_us=Some(0) constructed_after_us=Some(2) deadline_lower_us=Some(15000000) deadline_upper_us=Some(15000002) outcome_ok=Some(false) observed_us=Some(15001000) exact_deadline_known=false'
    slot='stress0-consent-slot index=0 observation=Some(([Some(1), Some(2), Some(3), Some(4), None, None, None, None, None], [None, None, None, None, None], 0))'
    sample='\n'.join([header,wait,slot,slot.replace('index=0','index=1')])
    unknown='stress0-consent-timing known=false loss_mask=1 snapshot_available=false'
    positives=[sample,unknown,sample.replace('known=true loss_mask=0','known=false loss_mask=2'),
        sample.replace(slot,'stress0-consent-slot index=0 observation=None'),
        sample.replace('outcome_ok=Some(false) observed_us=Some(15001000)','outcome_ok=None observed_us=None')]
    for value in positives: parse_consent_timing(value)
    require(not parse_consent_timing(sample)['all_milestones_observed'], 'missing-is-not-complete')
    require(parse_consent_timing(unknown)['slots'] is None, 'unavailable-is-null-not-empty')
    negatives=[sample+'\n'+header,sample.replace('index=1','index=0'),sample.replace('Some(15000002)','Some(15000003)'),
        sample.replace('exact_deadline_known=false','exact_deadline_known=true'),sample.replace('Some(1)','Some(-1)',1),
        sample.replace('Some(1)','Some(600000001)',1),sample.replace('loss_mask=0','loss_mask=128'),
        unknown.replace('known=false','known=true'),sample.replace('outcome_ok=Some(false)','outcome_ok=Some(Expired)'),
        sample.replace('], 0))','], 4294967296))'),sample.replace('observation=Some((', 'observation=Some(',1),
        sample.replace('snapshot_available=true','snapshot_available=false'),header,
        sample+'\nstress0-consent-unknown private=discard']
    for value in negatives:
        try: parse_consent_timing(value)
        except ValueError: continue
        raise ValueError('adversarial-timing-schema-accepted')
    return {'positive':len(positives),'negative':len(negatives),'runtime_bodies':0}
