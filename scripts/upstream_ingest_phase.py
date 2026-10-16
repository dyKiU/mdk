"""Bounded aggregate poll-wall and boundary-only thread CPU evidence."""
import copy
import json
import re
from upstream_completion_ci import ensure

PHASES = ['worker_delivery_ingest','account_runtime_ingest_engine_and_publication','app_effect_projection','account_sharing_observation','sharing_authentication','sibling_dispatch','automatic_dispatch','private_transport_evidence','post_ingest_route_refresh','post_ingest_checkpoint','transport_receipts']
COLUMNS = ['completed_polls','sum_wall_ns','max_wall_ns','stable_epoch','stable_completed','stable_sum_wall_ns','stable_max_wall_ns','straddling_completed','unwound_polls']

def integer(value): return type(value) is int and 0 <= value < 2**63

def clock_hz(raw):
    try:
        text = raw.decode('ascii') if isinstance(raw, bytes) else raw
        if not isinstance(text,str) or len(text)>32 or not re.fullmatch(r'[0-9]+\n?',text): return None
        value=int(text)
        return value if 0<value<=1_000_000 else None
    except (ValueError,UnicodeError): return None

def rows(value, count):
    ensure(isinstance(value,list) and len(value)==count,'row-inventory')
    for row in value:
        ensure(isinstance(row,list) and len(row)==9 and all(integer(item) for item in row),'row-schema')
        ensure(row[2]<=row[1] and row[6]<=row[5] and row[4]<=row[0] and row[5]<=row[1], 'row-counter-order')
        ensure(row[0]>0 or row[1]==row[2]==0,'empty-total')
        ensure(row[4]>0 or row[5]==row[6]==0,'empty-window')
    return value

def validate(value):
    ensure(isinstance(value,dict) and set(value)=={'boundary','epoch','wall_ns','thread_cpu_ticks','active_polls','unknown','workers','phases','active_phases'},'boundary-schema')
    ensure(value['boundary'] in {'start','end'} and integer(value['epoch']) and value['epoch']>0 and value['epoch']%2==1,'epoch')
    ensure(value['wall_ns'] is None or integer(value['wall_ns']),'wall')
    ensure(value['thread_cpu_ticks'] is None or isinstance(value['thread_cpu_ticks'],list) and len(value['thread_cpu_ticks'])==2 and all(integer(item) for item in value['thread_cpu_ticks']),'cpu')
    ensure(type(value['unknown']) is bool and integer(value['active_polls']) and value['active_polls']<=16,'active-workers')
    ensure(isinstance(value['active_phases'],list) and len(value['active_phases'])==11 and all(integer(item) and item<=16 for item in value['active_phases']),'active-phases')
    ensure(value['workers'] is None or isinstance(value['workers'],list) and len(value['workers'])<=16,'worker-bound')
    for name in ['workers','phases']:
        if value[name] is None: continue
        for row in rows(value[name],len(value[name]) if name=='workers' else 11):
            ensure(row[3] in {0,value['epoch']} and (row[3]!=0 or row[4]==row[5]==row[6]==0),'row-epoch')
    return value

def collect(raw,hz):
    report={'boundaries':[],'parse_rejections':0,'boundary_order_valid':False,'cpu_known':False,'phase_collection_complete':False,'poll_window_confident':False,'phase_names':PHASES,'columns':COLUMNS,'phase_units':['future_polls']*3+['synchronous_invocations']*8}
    def unique(pairs):
        ensure(len({key for key,_ in pairs})==len(pairs),'duplicate-field')
        return dict(pairs)
    positions=[]
    for match in re.finditer(r'(?m)^maintenance-phase[^\n]*',raw):
        try:
            line=match[0];ensure(line.startswith('maintenance-phase ') and len(line)<=30000 and len(report['boundaries'])<2,'boundary-capacity-or-prefix')
            report['boundaries'].append(validate(json.loads(line[len('maintenance-phase '):],object_pairs_hook=unique)));positions.append(match.start())
        except (ValueError,TypeError,IndexError,KeyError,json.JSONDecodeError): report['parse_rejections']+=1
    if report['parse_rejections'] or [row['boundary'] for row in report['boundaries']]!=['start','end']: return report
    start,end=report['boundaries']
    third=[m.start() for m in re.finditer(r'(?m)^automatic-enrollment-control stage=third-device-completed$',raw)]
    fourth=[m.start() for m in re.finditer(r'(?m)^automatic-enrollment-control stage=fourth-device-completion$',raw)]
    post=[m.start() for m in re.finditer(r'(?m)^automatic-enrollment-control (?:side=|existing_index=|stage=fourth-device-completed)',raw)]
    if len(third)!=1 or len(fourth)!=1 or not third[0]<positions[0]<fourth[0]<positions[1] or (post and positions[1]>=min(post)): return report
    if start['epoch']!=end['epoch'] or start['wall_ns'] is None or end['wall_ns'] is None or end['wall_ns']<start['wall_ns']: return report
    report['boundary_order_valid']=True;report['wall_ns']=end['wall_ns']-start['wall_ns']
    a,b=start['thread_cpu_ticks'],end['thread_cpu_ticks']
    if type(hz) is int and 0<hz<=1_000_000 and a is not None and b is not None and all(y>=x for x,y in zip(a,b)):
        report.update(cpu_known=True,cpu_ticks_delta=sum(b)-sum(a),cpu_seconds=(sum(b)-sum(a))/hz,hz=hz)
    if start['unknown'] or end['unknown'] or start['workers'] is None or end['workers'] is None or len(start['workers'])!=4 or len(end['workers'])!=4 or start['phases'] is None or end['phases'] is None: return report
    for name in ['workers','phases']:
        deltas=[]
        for before,after in zip(start[name],end[name]):
            if any(after[index]<before[index] for index in [0,1,2,7,8]): return report
            deltas.append({'completed':after[0]-before[0],'sum_wall_ns':after[1]-before[1], 'stable_window_completed':after[4] if after[3]==end['epoch'] else 0,'stable_window_sum_ns':after[5] if after[3]==end['epoch'] else 0,'stable_window_max_ns':after[6] if after[3]==end['epoch'] else 0,'straddling_completed':after[7]-before[7],'unwound':after[8]-before[8]})
        report[name]=deltas
    report['phase_collection_complete']=True
    report['poll_window_confident']=start['active_polls']==end['active_polls']==0 and not any(start['active_phases']+end['active_phases']) and all(not row['straddling_completed'] and not row['unwound'] for name in ['workers','phases'] for row in report[name])
    return report

def parser_preflight():
    start={'boundary':'start','epoch':1,'wall_ns':100,'thread_cpu_ticks':[10,2],'active_polls':0,'unknown':False,'workers':[[1,10,10,0,0,0,0,0,0] for _ in range(4)],'phases':[[1,10,10,0,0,0,0,0,0] for _ in range(11)],'active_phases':[0]*11}
    end=dict(copy.deepcopy(start),boundary='end',wall_ns=200,thread_cpu_ticks=[15,3],workers=[[3,50,30,1,2,40,30,0,0] for _ in range(4)],phases=[[3,50,30,1,2,40,30,0,0] for _ in range(11)])
    def raw(a,b): return 'automatic-enrollment-control stage=third-device-completed\nmaintenance-phase '+json.dumps(a)+'\nautomatic-enrollment-control stage=fourth-device-completion\nmaintenance-phase '+json.dumps(b)+'\nautomatic-enrollment-control side=left aggregate'
    good=collect(raw(start,end),100);ensure(good['cpu_known'] and good['cpu_ticks_delta']==6 and good['poll_window_confident'],'positive-poll-cpu');negative=0
    for bad in [None,True,-1,0,1000001,'',b'\xff',b'-100\n',b'0\n',b'1000001\n',b'100 extra',b'+100\n']:
        ensure(clock_hz(bad) is None,'hz-negative');negative+=1
    for key,value in [('thread_cpu_ticks',None),('thread_cpu_ticks',[9,3]),('wall_ns',99),('epoch',3)]:
        changed=dict(copy.deepcopy(end),**{key:value});ensure(not collect(raw(start,changed),100)['cpu_known'],'cpu-negative');negative+=1
    for key,value in [('active_polls',1),('active_phases',[1]+[0]*10),('unknown',True),('workers',None),('workers',end['workers'][:3]),('phases',None)]:
        changed=dict(copy.deepcopy(end),**{key:value});ensure(not collect(raw(start,changed),100)['poll_window_confident'],'inventory-or-active-negative');negative+=1
    for name in ['workers','phases']:
        for column in [7,8]:
            changed=copy.deepcopy(end);changed[name][0][column]=1;ensure(not collect(raw(start,changed),100)['poll_window_confident'],'straddle-unwind-negative');negative+=1
    for key,value in [('epoch',True),('epoch',2),('active_polls',17),('active_phases',[0]*10),('unknown',1),('workers',[[0]*9]*17),('phases',[[0]*9]*10),('thread_cpu_ticks',[-1,0])]:
        changed=dict(copy.deepcopy(end),**{key:value});ensure(collect(raw(start,changed),100)['parse_rejections']>0,'schema-negative');negative+=1
    sample=raw(start,end)
    for text in ['',sample+'\nmaintenance-phase '+json.dumps(end),sample.replace('"epoch": 1','"epoch": 1, "epoch": 1'),raw(end,start),sample.replace('stage=third-device-completed','stage=unknown'),sample.replace('stage=fourth-device-completion','stage=unknown'),sample.replace('automatic-enrollment-control side=left aggregate','maintenance-phase unknown')]:
        ensure(not collect(text,100)['poll_window_confident'],'missing-duplicate-phase-negative');negative+=1
    for key,value in [('unknown',True),('workers',None),('phases',None)]:
        changed=dict(copy.deepcopy(end),**{key:value})
        ensure(not collect(raw(start,changed),100)['phase_collection_complete'],'incomplete-collection-negative');negative+=1
    ensure(not collect(raw(start,end),None)['cpu_known'],'unknown-hz-negative');negative+=1
    ensure(clock_hz(b'100\n')==100 and clock_hz('1000')==1000,'hz-positive')
    return {'positive_controls':3,'negative_controls':negative,'actual_product_bodies':0}
