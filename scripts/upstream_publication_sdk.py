"""Bounded numeric SDK snapshots; never infer an owner from an SDK ordinal."""
import copy
import json
import re
from upstream_completion_ci import ensure

STAGES = ['sdk-entry','prepared-single','operation-returned','retain-lock-start','retain-lock-acquired','retain-eviction-returned','connect-start','connect-returned','sdk-send-start','sdk-send-returned','aborted-join-drain-start','aborted-join-drain-returned','ambiguous-reset-start','ambiguous-reset-returned','single-release-start','single-release-returned','release-lock-start','release-lock-acquired','release-eviction-start','release-eviction-returned']

def unique_fields(pairs):
    ensure(len({key for key,_ in pairs}) == len(pairs), 'duplicate-sdk-field')
    return dict(pairs)

def numeric(row, width):
    return isinstance(row,list) and len(row)==width and all(type(value) is int and 0<=value<2**63 for value in row)

def validate(value):
    ensure(isinstance(value,dict) and set(value)=={'at_ms','messages','operations','unknown'}, 'sdk-schema')
    ensure(type(value['at_ms']) is int and 0<value['at_ms']<2**63 and numeric(value['unknown'],6), 'sdk-scalars')
    messages=value['messages']; operations=value['operations']
    ensure(isinstance(messages,list) and len(messages)<=128 and all(numeric(row,5) for row in messages), 'sdk-messages')
    ensure([row[0] for row in messages]==list(range(1,len(messages)+1)), 'sdk-message-token-order')
    ensure(all(row[1]<=2 and row[2]<=1 and row[3]>0 and row[4]<=1 for row in messages), 'sdk-message-context')
    ensure(all(row[1]==2 or (row[1]==0 and row[2]==0) or (row[1]==1 and row[2]==1) for row in messages), 'sdk-message-role')
    ensure(isinstance(operations,list) and len(operations)<=128, 'sdk-operation-capacity')
    ensure([row.get('ordinal') for row in operations]==list(range(1,len(operations)+1)), 'sdk-operation-order')
    for operation in operations:
        ensure(set(operation)=={'ordinal','token','endpoints','stages'}, 'sdk-operation-schema')
        ensure(type(operation['ordinal']) is int, 'sdk-operation-ordinal-type')
        ensure(type(operation['token']) is int and 1<=operation['token']<=len(messages), 'sdk-operation-token')
        ensure(type(operation['endpoints']) is int and 0<=operation['endpoints']<2**63, 'sdk-endpoints')
        stages=operation['stages']; ensure(isinstance(stages,list) and len(stages)==20 and all(numeric(row,3) for row in stages), 'sdk-stage-shape')
        entry=stages[0]
        ensure(entry[2]==1 and 0<entry[0]==entry[1]<=value['at_ms'], 'sdk-operation-entry')
        for first,last,count in stages:
            ensure((count==0 and first==last==0) or (count>0 and entry[0]<=first<=last<=value['at_ms']), 'sdk-stage-time')
            if count==1: ensure(first==last, 'sdk-one-stage-one-timestamp')
        ensure(stages[1][2]<=1 and stages[2][2]<=1, 'sdk-terminal-counts')
        if stages[2][2]:
            ensure(stages[1][2]==1 and stages[1][0]<=stages[2][0], 'sdk-return-without-prepared')
        for index,row in enumerate(stages[3:],3):
            if row[2]: ensure(stages[1][2]==1 and stages[1][0]<=row[0], 'sdk-inner-stage-without-prepared')
            if row[2] and stages[2][2]: ensure(row[1]<=stages[2][0], 'sdk-inner-stage-after-return')
        for before,after in [(3,4),(4,5),(6,7),(8,9),(10,11),(12,13),(14,15),(16,17),(17,18),(18,19)]:
            first,last=stages[before],stages[after]
            if last[2]:
                ensure(first[2]>=last[2] and first[0]<=last[0], 'sdk-return-without-ordered-start')
                if first[2]==last[2]: ensure(first[1]<=last[1], 'sdk-equal-count-last-event-order')
    return value

def collect(raw, probes):
    result={'snapshot_valid':False,'association_complete':False,'logical_message_association_complete':False,'per_generation_association_unique':False,'per_generation':[],'stage_names':STAGES}
    try:
        lines=re.findall(r'(?m)^completion-sdk (.*)$',raw)
        ensure(len(lines)==1 and len(lines[0])<=300_000, 'one-bounded-sdk-snapshot')
        value=validate(json.loads(lines[0],object_pairs_hook=unique_fields)); result['snapshot']=value
        position=raw.index('completion-sdk ')
        costs=[match.start() for match in re.finditer(r'(?m)^completion-cost ',raw)]
        post=[match.start() for match in re.finditer(r'(?m)^(?:completion-diag |automatic-enrollment-control side=|automatic-enrollment-control stage=fourth-device-completed)',raw)]
        ensure(len(costs)==2 and costs[1]<position and (not post or position<min(post)), 'sdk-post-verdict-pre-observation-boundary')
        result['snapshot_valid']=not any(value['unknown'][index] for index in [0,1,2,4]) and not any(row[4] for row in value['messages'])
        messages={row[0]:row for row in value['messages']}; complete=bool(probes)
        for index,probe in enumerate(probes):
            for row in probe['rows']:
                token=row[17]; registration=row[18]; context=messages.get(token)
                operations=[operation['ordinal'] for operation in value['operations'] if operation['token']==token]
                known=context is not None and context[1]==row[1] and context[4]==0 and 0<registration<=context[3] and bool(operations)
                status='unknown_or_post_snapshot' if not known else 'unique_registration' if context[3]==1 else 'ambiguous_multiple_app_registrations'
                result['per_generation'].append({'probe_dump_index':index,'generation':row[0],'token':token,'registration':registration,'operations':operations,'association':status})
                complete &= known
        result['association_complete']=bool(result['snapshot_valid'] and complete)
        result['logical_message_association_complete']=result['association_complete']
        result['per_generation_association_unique']=result['logical_message_association_complete'] and all(row['association']=='unique_registration' for row in result['per_generation'])
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,json.JSONDecodeError) as error:
        result['failure']=str(error) if isinstance(error,ValueError) else type(error).__name__
    return result

def parser_preflight():
    stages=[[0,0,0] for _ in STAGES]; stages[0]=[1,1,1]; stages[1]=[2,2,1]; stages[8]=[3,4,2]
    snapshot={'at_ms':5,'messages':[[1,1,1,1,0]],'operations':[{'ordinal':1,'token':1,'endpoints':1,'stages':stages}],'unknown':[0]*6}
    probe={'rows':[[1,1]+[0]*15+[1,1]]}
    def raw(value): return 'completion-cost start\ncompletion-cost end\ncompletion-sdk '+json.dumps(value)+'\ncompletion-diag later'
    ensure(collect(raw(snapshot),[probe])['association_complete'], 'sdk-unique-positive')
    repeated=copy.deepcopy(snapshot); repeated['messages'][0][3]=2
    result=collect(raw(repeated),[probe]); ensure(result['logical_message_association_complete'] and not result['per_generation_association_unique'] and result['per_generation'][0]['association']=='ambiguous_multiple_app_registrations','sdk-logical-retry-ambiguous-positive')
    parallel=copy.deepcopy(snapshot); parallel['operations'][0]['stages'][8]=[2,5,2]; parallel['operations'][0]['stages'][9]=[3,3,1]
    ensure(collect(raw(parallel),[probe])['snapshot_valid'],'sdk-parallel-unfinished-start-positive')
    bad=[]
    for key,value in [('at_ms',0),('unknown',[0]*4),('messages',[[0,1,1,1,0]]),('messages',[[1,3,1,1,0]])]:
        changed=copy.deepcopy(snapshot); changed[key]=value; bad.append(raw(changed))
    for field,value in [('token',2),('ordinal',2),('ordinal',True),('endpoints',-1),('stages',[[0]*3]*19)]:
        changed=copy.deepcopy(snapshot); changed['operations'][0][field]=value; bad.append(raw(changed))
    for column,value in [(0,[0,0,1]),(1,[2,6,1]),(2,[2,2,2]),(3,[0,1,0])]:
        changed=copy.deepcopy(snapshot); changed['operations'][0]['stages'][column]=value; bad.append(raw(changed))
    for before,after in [(3,4),(4,5),(6,7),(8,9),(10,11),(12,13),(14,15),(16,17),(17,18),(18,19)]:
        changed=copy.deepcopy(snapshot); changed['operations'][0]['stages']=[[0,0,0] for _ in STAGES]; changed['operations'][0]['stages'][0]=[1,1,1]; changed['operations'][0]['stages'][1]=[2,2,1]
        changed['operations'][0]['stages'][after]=[3,3,1]; bad.append(raw(changed))
    for kind,role in [(0,1),(1,0)]:
        changed=copy.deepcopy(snapshot); changed['messages'][0][1:3]=[kind,role]; bad.append(raw(changed))
    bad.extend(['',raw(snapshot)+'\ncompletion-sdk '+json.dumps(snapshot),raw(snapshot).replace('"at_ms": 5','"at_ms": 5, "at_ms": 5'),'completion-sdk '+json.dumps(snapshot)+'\ncompletion-cost start\ncompletion-cost end'])
    for text in bad: ensure(not collect(text,[probe])['snapshot_valid'],'sdk-malformed-negative')
    for index in [0,1,2,4]:
        changed=copy.deepcopy(snapshot); changed['unknown'][index]=1
        ensure(not collect(raw(changed),[probe])['association_complete'],'sdk-overflow-unknown-negative')
    for change in ['missing','mismatch','token','kind','post_snapshot','zero_registration']:
        changed=copy.deepcopy(snapshot); selected=copy.deepcopy(probe)
        if change=='missing': changed['operations']=[]
        if change=='mismatch': changed['messages'][0][4]=1
        if change=='token': selected['rows'][0][17]=0
        if change=='kind': selected['rows'][0][1]=2
        if change=='post_snapshot': selected['rows'][0][18]=2
        if change=='zero_registration': selected['rows'][0][18]=0
        ensure(not collect(raw(changed),[selected])['association_complete'],'sdk-missing-association-negative')
    return {'positive_controls':3,'negative_controls':len(bad)+10,'actual_product_bodies':0}
