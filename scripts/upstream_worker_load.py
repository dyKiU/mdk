"""Boundary-only thread CPU ticks and fixed worker-poll aggregate evidence."""
import copy
import json
import re
import subprocess
from upstream_completion_ci import ensure

def clock_hz(raw):
    try:
        text=raw.decode('ascii') if isinstance(raw,bytes) else raw
        if not isinstance(text,str) or len(text)>32 or not re.fullmatch(r'[0-9]+\n?',text): return None
        value=int(text)
        return value if 0<value<=1_000_000 else None
    except (ValueError,UnicodeError): return None

def read_hz():
    try:
        result=subprocess.run(['getconf','CLK_TCK'],capture_output=True,timeout=5)
        return {'hz':clock_hz(result.stdout) if result.returncode==0 else None,'getconf_exit_code':result.returncode}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'hz':None,'getconf_error':type(error).__name__}

def integers(row,width):
    return isinstance(row,list) and len(row)==width and all(type(value) is int and 0<=value<2**63 for value in row)

def validate(value):
    ensure(isinstance(value,dict) and set(value)=={'boundary','epoch','wall_ns','thread_cpu_ticks','active_polls','unknown','workers'}, 'load-schema')
    ensure(value['boundary'] in {'start','end'} and type(value['epoch']) is int and 0<value['epoch']<2**63 and value['epoch']%2==1, 'load-boundary-epoch')
    ensure(value['wall_ns'] is None or type(value['wall_ns']) is int and 0<=value['wall_ns']<2**63, 'load-wall')
    ensure(value['thread_cpu_ticks'] is None or integers(value['thread_cpu_ticks'],2), 'load-cpu-ticks')
    ensure(type(value['unknown']) is bool and type(value['active_polls']) is int and 0<=value['active_polls']<=16, 'load-active-or-unknown')
    rows=value['workers']
    ensure(rows is None or isinstance(rows,list) and len(rows)<=16 and all(integers(row,9) for row in rows), 'load-workers')
    for row in rows or []:
        ensure(row[2]<=row[1] and row[6]<=row[5] and row[4]<=row[0] and row[5]<=row[1], 'load-counter-order')
        ensure(row[0]>0 or row[1]==row[2]==0, 'load-empty-total')
        ensure(row[4]>0 or row[5]==row[6]==0, 'load-empty-window')
        ensure(row[3] in {0,value['epoch']} and (row[3]!=0 or row[4]==row[5]==row[6]==0), 'load-window-epoch')
    return value

def collect(raw,hz):
    report={'boundaries':[],'cpu_known':False,'poll_window_confident':False,'parse_rejections':0}
    def unique(pairs):
        ensure(len({key for key,_ in pairs})==len(pairs),'duplicate-load-json-field')
        return dict(pairs)
    for line in raw.splitlines():
        if not line.startswith('completion-load '): continue
        try:
            ensure(len(line)<=20_000 and len(report['boundaries'])<2,'load-capacity')
            report['boundaries'].append(validate(json.loads(line[len('completion-load '):],object_pairs_hook=unique)))
        except (ValueError,TypeError,IndexError,KeyError,json.JSONDecodeError): report['parse_rejections']+=1
    if report['parse_rejections'] or [row['boundary'] for row in report['boundaries']]!=['start','end']: return report
    start,end=report['boundaries']
    if start['epoch']!=end['epoch'] or start['wall_ns'] is None or end['wall_ns'] is None or end['wall_ns']<start['wall_ns']: return report
    positions=[match.start() for match in re.finditer(r'(?m)^completion-load ',raw)]
    costs=[match.start() for match in re.finditer(r'(?m)^completion-cost ',raw)]
    phase=raw.find('automatic-enrollment-control stage=fourth-device-completion')
    post=[match.start() for match in re.finditer(r'(?m)^(?:completion-sdk |completion-diag |automatic-enrollment-control side=|automatic-enrollment-control stage=fourth-device-completed)',raw)]
    report['boundary_order_valid']=len(costs)==2 and costs[0]<positions[0]<phase<costs[1]<positions[1] and (not post or positions[1]<min(post))
    report['wall_ns']=end['wall_ns']-start['wall_ns']
    cpu_start,cpu_end=start['thread_cpu_ticks'],end['thread_cpu_ticks']
    if type(hz) is int and 0<hz<=1_000_000 and cpu_start is not None and cpu_end is not None and all(after>=before for before,after in zip(cpu_start,cpu_end)):
        ticks=sum(cpu_end)-sum(cpu_start)
        report.update(cpu_ticks_delta=ticks,cpu_seconds=ticks/hz,hz=hz,cpu_known=report['boundary_order_valid'])
    first,last=start['workers'],end['workers']
    if start['unknown'] or end['unknown'] or first is None or last is None or len(first)!=4 or len(last)!=4: return report
    deltas=[]
    for before,after in zip(first,last):
        if any(after[index]<before[index] for index in [0,1,2,7,8]): return report
        deltas.append({'completed':after[0]-before[0],'sum_wall_ns':after[1]-before[1],
            'stable_window_completed':after[4] if after[3]==end['epoch'] else 0,
            'stable_window_sum_ns':after[5] if after[3]==end['epoch'] else 0,
            'stable_window_max_ns':after[6] if after[3]==end['epoch'] else 0,
            'straddling_completed':after[7]-before[7],'unwound':after[8]-before[8]})
    report['workers']=deltas
    report['poll_window_confident']=report['boundary_order_valid'] and start['active_polls']==end['active_polls']==0 and all(row['straddling_completed']==0 and row['unwound']==0 for row in deltas)
    return report

def parser_preflight():
    start={'boundary':'start','epoch':1,'wall_ns':100,'thread_cpu_ticks':[10,2],'active_polls':0,'unknown':False,'workers':[[1,10,10,0,0,0,0,0,0] for _ in range(4)]}
    end={'boundary':'end','epoch':1,'wall_ns':200,'thread_cpu_ticks':[15,3],'active_polls':0,'unknown':False,'workers':[[3,50,30,1,2,40,30,0,0] for _ in range(4)]}
    def raw(first,last): return 'completion-cost start\ncompletion-load '+json.dumps(first)+'\nautomatic-enrollment-control stage=fourth-device-completion\ncompletion-cost end\ncompletion-load '+json.dumps(last)+'\ncompletion-sdk later'
    result=collect(raw(start,end),100); ensure(result['cpu_known'] and result['cpu_ticks_delta']==6 and result['poll_window_confident'],'load-positive')
    ensure(clock_hz(b'100\n')==100 and clock_hz('1000')==1000,'hz-positives')
    negatives=0
    for bad in [None,True,-1,0,1000001,'',b'\xff',b'-100\n',b'0\n',b'1000001\n',b'100 extra',b'+100\n']:
        ensure(clock_hz(bad) is None,'hz-negatives'); negatives+=1
    for key,value in [('thread_cpu_ticks',None),('thread_cpu_ticks',[9,3]),('wall_ns',99),('epoch',3)]:
        changed=copy.deepcopy(end);changed[key]=value
        ensure(not collect(raw(start,changed),100)['cpu_known'],'cpu-missing-nonmonotonic-negative'); negatives+=1
    ensure(not collect(raw(start,end),None)['cpu_known'],'missing-hz-negative'); negatives+=1
    for key,value in [('active_polls',1),('unknown',True),('workers',None),('workers',end['workers'][:3])]:
        changed=copy.deepcopy(end);changed[key]=value
        ensure(not collect(raw(start,changed),100)['poll_window_confident'],'poll-partial-negative'); negatives+=1
    for column in [7,8]:
        changed=copy.deepcopy(end);changed['workers'][0][column]=1
        ensure(not collect(raw(start,changed),100)['poll_window_confident'],'straddling-unwind-negative'); negatives+=1
    for key,value in [('epoch',True),('epoch',2),('active_polls',17),('unknown',1),('workers',[[0]*9]*17),('thread_cpu_ticks',[-1,0])]:
        changed=copy.deepcopy(end);changed[key]=value
        ensure(collect(raw(start,changed),100)['parse_rejections']>0,'load-malformed-negative'); negatives+=1
    for text in ['',raw(start,end)+'\ncompletion-load '+json.dumps(end),raw(start,end).replace('"epoch": 1','"epoch": 1, "epoch": 1'),raw(end,start)]:
        ensure(not collect(text,100)['poll_window_confident'],'load-missing-duplicate-order-negative'); negatives+=1
    return {'positive_controls':3,'negative_controls':negatives,'actual_product_bodies':0}
