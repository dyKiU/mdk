"""Strict closed numeric parser; never return raw diagnostic text."""
import json
import re
ENUMS = {'VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete','Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite','BeforeCoreWrap','AfterCoreWrap','BeforeRelayPublication','AfterRelayPublication'}
REASONS = {'VerifierFallback','NoRound','GuardInvalid','NoSettledRoster','SharingPending','Complete'}
FAILURES = {'Owner','Collection','Runtime','Engine','Genesis','Gate','PrivateInvite'}
STAGES = {'BeforeCoreWrap','AfterCoreWrap','BeforeRelayPublication','AfterRelayPublication'}
COUNTERS = ['attempts','hits','cold_calls','bypass','lookup_poison','insert_poison','insertions','evictions','verifier_ok','verifier_error','cpu_ns','wall_ns','unknown_cpu','cpu_read_failures','active','entries_peak']
GLOBAL = ['calls','ok','error','cpu_ns','wall_ns','unknown_cpu','cpu_read_failures','active']
class SchemaError(ValueError): pass
def require(ok):
    if not ok: raise SchemaError('closed-diagnostic-schema')
def number(value): return type(value) is int and 0 <= value <= (1 << 64)-1
def numbers(value,size): return isinstance(value,list) and len(value)==size and all(number(item) for item in value)
def optional(value,check): return value is None or check(value)
def rust(value):
    require(len(value)<=32768)
    tokens=re.findall(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[()[\],]',value)
    require(''.join(tokens)==re.sub(r'\s+','',value) and len(tokens)<=4096)
    index=0
    def parse():
        nonlocal index
        require(index<len(tokens)); token=tokens[index]; index+=1
        if token=='Some':
            require(index<len(tokens) and tokens[index]=='('); index+=1
            result=parse(); require(index<len(tokens) and tokens[index]==')'); index+=1
            return result
        if token=='None': return None
        if token in ['true','false']: return token=='true'
        if token in ENUMS: return token
        if token.isdigit():
            result=int(token); require(number(result)); return result
        require(token in ['[','(']); closing=']' if token=='[' else ')'; result=[]
        while index<len(tokens) and tokens[index]!=closing:
            result.append(parse())
            if index<len(tokens) and tokens[index]==',': index+=1
            else: break
        require(index<len(tokens) and tokens[index]==closing); index+=1
        return result
    result=parse(); require(index==len(tokens)); return result

def child(value):
    return isinstance(value,list) and len(value)==5 and all(number(item) for item in value[:3]) and value[0]<=255 and optional(value[3],lambda v:v in FAILURES) and optional(value[4],lambda v:v in STAGES)
def observation(value):
    return isinstance(value,list) and len(value)==3 and numbers(value[0],6) and numbers(value[1],6) and optional(value[2],lambda v:isinstance(v,list) and len(v)==2 and v[0] in REASONS and number(v[1]))

def parse_existing(raw,phase):
    result={'sides':{},'existing_sources':[],'phase':phase,'timestamps_are_last_observations_not_durations':True,'cached_terminal_refresh_can_bypass_stage_counts':True}
    seen=set()
    for line in raw.splitlines():
        if not line.startswith('automatic-enrollment-control '): continue
        if line.startswith('automatic-enrollment-control stage='): continue
        match=re.fullmatch(r'automatic-enrollment-control side=(left|right) primary/expected/children/completed=(.*?) intake=(.*?) rejections=(.*?) context_rejections=(.*?) projection=(.*)',line)
        if match:
            side=match[1]; require(('aggregate',side) not in seen); seen.add(('aggregate',side))
            completion,intake,rejections,context,projection=[rust(match[i]) for i in range(2,7)]
            require(optional(completion,lambda v:isinstance(v,list) and len(v)==4 and type(v[0]) is bool and optional(v[1],number) and number(v[2]) and number(v[3])))
            for value,size in [(intake,8),(rejections,4),(context,9),(projection,4)]: require(optional(value,lambda v:numbers(v,size)))
            result['sides'].setdefault(side,{})['protocol']={'primary_expected_children_completed':completion,'intake':intake,'rejections':rejections,'context_rejections':context,'projection':projection}
            continue
        match=re.fullmatch(r'automatic-enrollment-control side=(left|right) child_channels=(.*)',line)
        if match:
            side=match[1]; require(('children',side) not in seen); seen.add(('children',side)); value=rust(match[2])
            require(optional(value,lambda v:isinstance(v,list) and len(v)<=128 and all(child(item) for item in v)))
            result['sides'].setdefault(side,{})['children']=value; continue
        match=re.fullmatch(r'automatic-enrollment-control side=(left|right) native_rpc_counts/elapsed_ms/branch=(.*)',line)
        if match:
            side=match[1]; require(('rpc',side) not in seen); seen.add(('rpc',side)); value=rust(match[2]); require(optional(value,observation))
            result['sides'].setdefault(side,{})['native_rpc']=value; continue
        match=re.fullmatch(r'automatic-enrollment-control existing_index=([0-9]+) child_channel=(.*)',line)
        if match:
            index=int(match[1]); require(index<128 and ('source',index) not in seen); seen.add(('source',index)); value=rust(match[2]); require(optional(value,child))
            result['existing_sources'].append({'index':index,'role':{0:'existing-B',1:'existing-C'}.get(index,'unmapped-existing-index'),'channel':value}); continue
        raise SchemaError('unknown-existing-diagnostic-record')
    for side,record in result['sides'].items():
        require(set(record)=={'protocol','children','native_rpc'})
        record['role']='sponsor-A' if side=='left' else 'recipient-C' if phase=='third' else 'recipient-D' if phase=='fourth' else 'unmapped-phase'
    require(not result['sides'] or set(result['sides'])=={'left','right'})
    result['failure_snapshots_observed']=bool(result['sides'])
    return result

def parse_cost(raw):
    rows=[]
    expected_keys={'phase','completion_success_marker','panicking','phase_cpu_ns','phase_wall_ns','phase_cpu_read_failures','observer_cpu_reads','engine_capacity','engine_overflow','phase_conflicts','counter_names','global_names','global','engines','cpu_resolution','cpu_scope','observer_overhead'}
    for line in raw.splitlines():
        if not line.startswith('proof-memo-cost-diagnostic '): continue
        require(len(line)<=65536)
        row=json.loads(line.split(' ',1)[1]); require(set(row)==expected_keys)
        require(row['phase'] in ['third','fourth'] and all(old['phase']!=row['phase'] for old in rows))
        require(type(row['completion_success_marker']) is bool and type(row['panicking']) is bool)
        require(optional(row['phase_cpu_ns'],number) and all(number(row[key]) for key in ['phase_wall_ns','phase_cpu_read_failures','observer_cpu_reads','engine_capacity','engine_overflow','phase_conflicts']))
        require(row['engine_capacity']==16 and row['counter_names']==COUNTERS and row['global_names']==GLOBAL and numbers(row['global'],8))
        require(isinstance(row['engines'],list) and len(row['engines'])<=16)
        require(row['cpu_resolution']=='unknown; zero deltas may be quantized')
        require(row['cpu_scope']=='scheduled current thread shared across actors; synchronous verifier spans inclusive and nested')
        require(row['observer_overhead']=='relaxed atomics and two schedstat reads per timed span; no per-call registry mutex, allocation or logging')
        for ordinal,entry in enumerate(row['engines']):
            require(set(entry)=={'ordinal','created_ms_since_first_registration','dropped_ms_since_first_registration','alive_at_snapshot','counts','outside_counts'})
            require(entry['ordinal']==ordinal and number(entry['created_ms_since_first_registration']) and optional(entry['dropped_ms_since_first_registration'],number) and type(entry['alive_at_snapshot']) is bool and entry['alive_at_snapshot']==(entry['dropped_ms_since_first_registration'] is None))
            require(numbers(entry['counts'],16) and numbers(entry['outside_counts'],16))
        rows.append(row)
    require(len(rows)<=2)
    return rows

def preflight():
    checks=0
    for reason in sorted(REASONS):
        value=rust('Some(([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6], Some(('+reason+', 7))))'); require(observation(value)); checks+=1
    for failure in sorted(FAILURES):
        for stage in sorted(STAGES): require(child(rust('Some((255, 1, 0, Some('+failure+'), Some('+stage+')))'))); checks+=1
    require(rust('None') is None); require(rust('Some((true, Some(2), 2, 0))')==[True,2,2,0]); checks+=2
    for invalid in ['Some(account_id)', 'Some((UnknownReason, 1))', 'Some([1, "private"])', '-1', '1 trailing', str(1<<65)]:
        try: rust(invalid)
        except SchemaError: checks+=1
        else:
            # A known syntactic shape with unknown enum must still be rejected.
            raise SchemaError('negative-parser-fixture-accepted')
    sample={'phase':'third','completion_success_marker':True,'panicking':False,'phase_cpu_ns':1,'phase_wall_ns':1,'phase_cpu_read_failures':0,'observer_cpu_reads':2,'engine_capacity':16,'engine_overflow':0,'phase_conflicts':0,'counter_names':COUNTERS,'global_names':GLOBAL,'global':[1,1,0,1,1,0,0,0],'engines':[{'ordinal':0,'created_ms_since_first_registration':0,'dropped_ms_since_first_registration':None,'alive_at_snapshot':True,'counts':[1,0,1,0,0,0,1,0,1,0,1,1,0,0,0,1],'outside_counts':[0]*16}],'cpu_resolution':'unknown; zero deltas may be quantized','cpu_scope':'scheduled current thread shared across actors; synchronous verifier spans inclusive and nested','observer_overhead':'relaxed atomics and two schedstat reads per timed span; no per-call registry mutex, allocation or logging'}
    require(len(parse_cost('proof-memo-cost-diagnostic '+json.dumps(sample)))==1); checks+=1
    malformed=dict(sample,counter_names=COUNTERS+['unknown'])
    try: parse_cost('proof-memo-cost-diagnostic '+json.dumps(malformed))
    except SchemaError: checks+=1
    else: raise SchemaError('unknown-counter-fixture-accepted')
    lines=[]
    for side in ['left','right']:
        lines += ['automatic-enrollment-control side='+side+' primary/expected/children/completed=Some((true, Some(2), 2, 0)) intake=Some([1, 2, 3, 4, 5, 6, 7, 8]) rejections=Some([0, 0, 0, 0]) context_rejections=Some([0, 0, 0, 0, 0, 0, 0, 0, 0]) projection=Some([1, 2, 3, 4])',
                  'automatic-enrollment-control side='+side+' child_channels=Some([(31, 2, 0, None, Some(AfterRelayPublication))])',
                  'automatic-enrollment-control side='+side+' native_rpc_counts/elapsed_ms/branch=Some(([1, 1, 1, 1, 1, 1], [1, 1, 1, 1, 1, 1], Some((SharingPending, 1))))']
    lines += ['automatic-enrollment-control existing_index=0 child_channel=Some((31, 2, 0, None, Some(AfterRelayPublication)))']
    require(parse_existing('\n'.join(lines),'fourth')['sides']['right']['role']=='recipient-D'); checks+=1
    for malformed in [lines+lines[:1],lines[:-2],lines+['automatic-enrollment-control private=forbidden']]:
        try: parse_existing('\n'.join(malformed),'fourth')
        except SchemaError: checks+=1
        else: raise SchemaError('malformed-existing-fixture-accepted')
    return {'fixed_schema_positive_and_negative_checks':checks,'actual_product_bodies':0}
