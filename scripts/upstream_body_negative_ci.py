"""Remote-only bounded oracles for same-channel, different-chat negative retention."""
import copy
import re
from pathlib import Path
from upstream_completion_ci import ensure, parse_body, headers
BASE='a5b1d906134f566580c65a1372211ff751f92eef'
CASE='authenticated_negative_sql_failure_retains_owned_body_until_commit_before_harvest'
TEST='crates/marmot-app/src/native_device_linking/tests/automatic_body_negative_acceptance.rs'
PRODUCT='crates/marmot-app/src/client/account_chat_sharing/automatic.rs'
MESSAGE='authenticated negative SQL rollback must retain the same owned Body until negative commit precedes aborted-task harvest without old Body effects'
ANCHOR='''                // Retain the owned slot as a barrier until this authenticated
                // negative assembly commits. Renewal would discard its retry.
                if let Some(publication) = entry.publication.as_ref() {'''
MUTANT='''                // Retain the owned slot as a barrier until this authenticated
                // negative assembly commits. Renewal would discard its retry.
                entry.renew = true;
                if let Some(publication) = entry.publication.as_ref() {'''
STAGES=['actual-owned-body-held','actual-authenticated-negative-sql-failure','persistent-sql-fault-removed']
FLAGS=['retained','commit_before_harvest','no_old_body_effects','actor_progress']
def panic_line():
    source=Path(TEST).read_text();ensure(source.count(MESSAGE)==1,'one-own-negative-oracle')
    location=source.rfind('assert!(',0,source.index(MESSAGE));ensure(location>=0,'own-assertion-location')
    return source[:location].count('\n')+1

def parse(raw):
    row=parse_body(raw,CASE)
    row['compiler_error_count']=headers(raw)['compiler_error_count']
    row['executed_case_names']=re.findall(r'(?m)^test ([A-Za-z0-9_:]+) \.\.\.',raw)
    row['stages']=re.findall(r'(?m)^body-negative-control stage=([a-z-]+)(?: index=(\d+))?$',raw)
    rows=re.findall(r'(?m)^body-negative-control retained=(true|false) commit_before_harvest=(true|false) no_old_body_effects=(true|false) actor_progress=(true|false) sql_failures=(\d+) barrier_observations=(\d+) commit_at=(\d+) harvest_at=(\d+) body_effects=(\d+)$',raw)
    if len(rows)==1:
        row['observed']={key:value=='true' for key,value in zip(FLAGS,rows[0][:4])}
        row['observed'].update(dict(zip(['sql_failures','barrier_observations','commit_at','harvest_at','body_effects'],map(int,rows[0][4:]))))
    row['named_oracle_count']=raw.count(MESSAGE)
    return row

def prerequisites(row):
    stages=row.get('stages',[]);observed=row.get('observed',{})
    names=row.get('executed_case_names',[])
    return isinstance(names,list) and len(names)==1 and type(names[0]) is str and names[0].endswith('::'+CASE) and exact_numbers(row,{'compiler_error_count':0}) and isinstance(stages,list) and all(isinstance(item,(list,tuple)) and len(item)==2 and all(type(value) is str for value in item) for item in stages) and [tuple(item) for item in stages]==[(stage,'') for stage in STAGES]+[('positive-runtime-close','0'),('positive-runtime-close','1')] and all(type(observed.get(key)) is bool for key in FLAGS) and all(type(observed.get(key)) is int and 0<=observed[key]<2**63 for key in ['sql_failures','barrier_observations','commit_at','harvest_at','body_effects']) and observed['sql_failures']>0

def exact_numbers(row,values):
    return all(type(row.get(key)) is int and row[key]==value for key,value in values.items())

def green(row):
    return prerequisites(row) and exact_numbers(row,{'body_exit_code':0,'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'all_panic_header_count':0,'named_oracle_count':0}) and not row.get('watchdog_triggered') and all(row['observed'][key] for key in FLAGS) and row['observed']['barrier_observations']>0 and 0<row['observed']['commit_at']<row['observed']['harvest_at'] and row['observed']['body_effects']==0

def intended_red(row):
    return prerequisites(row) and exact_numbers(row,{'body_exit_code':101,'passed':0,'failed':1,'ignored':0,'executed_nonignored':1,'all_panic_header_count':1,'named_oracle_count':1}) and row.get('panic_locations')==[{'file':TEST,'line':panic_line(),'column':5}] and not row.get('watchdog_triggered') and row.get('observed',{}).get('retained') is False

def parser_preflight():
    observed={'retained':True,'commit_before_harvest':True,'no_old_body_effects':True,'actor_progress':True,'sql_failures':2,'barrier_observations':1,'commit_at':1,'harvest_at':2,'body_effects':0}
    control={'stages':[(stage,'') for stage in STAGES]+[('positive-runtime-close','0'),('positive-runtime-close','1')],'observed':observed,'body_exit_code':0,'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'all_panic_header_count':0,'named_oracle_count':0,'compiler_error_count':0,'executed_case_names':['fixture::'+CASE]}
    ensure(green(control),'green-oracle-positive')
    red=copy.deepcopy(control);red.update(body_exit_code=101,passed=0,failed=1,all_panic_header_count=1,named_oracle_count=1,panic_locations=[{'file':TEST,'line':panic_line(),'column':5}]);red['observed']['retained']=False
    ensure(intended_red(red),'runtime-red-oracle-positive')
    negatives=0
    for key,value in [('body_exit_code',1),('passed',1),('failed',0),('ignored',1),('executed_nonignored',0),('all_panic_header_count',2),('named_oracle_count',0),('panic_locations',[]),('watchdog_triggered',True),('stages',red['stages'][:-1]),('compiler_error_count',1),('compiler_error_count',False),('executed_case_names',[]),('executed_case_names',['fixture::wrong_case'])]:
        bad=copy.deepcopy(red);bad[key]=value;ensure(not intended_red(bad),'red-rejects-unqualified-runtime');negatives+=1
    for key,value in [('retained',True),('retained','false'),('sql_failures',0),('sql_failures',True),('sql_failures',2**63)]:
        bad=copy.deepcopy(red);bad['observed'][key]=value;ensure(not intended_red(bad),'red-rejects-missing-real-witness');negatives+=1
    for key,value in [('retained',False),('commit_before_harvest',False),('no_old_body_effects',False),('actor_progress',False),('barrier_observations',0),('commit_at',3),('body_effects',1)]:
        bad=copy.deepcopy(control);bad['observed'][key]=value;ensure(not green(bad),'green-rejects-incomplete-proof');negatives+=1
    raw_stages='\n'.join('body-negative-control stage='+stage+(' index='+index if index else '') for stage,index in control['stages'])+'\n'
    record='body-negative-control retained=true commit_before_harvest=true no_old_body_effects=true actor_progress=true sql_failures=2 barrier_observations=1 commit_at=1 harvest_at=2 body_effects=0\n'
    raw_green='test fixture::'+CASE+' ... ok\n'+raw_stages+record+'test result: ok. 1 passed; 0 failed; 0 ignored;\n'
    parsed=parse(raw_green);parsed['body_exit_code']=0;ensure(green(parsed),'actual-format-green-parser')
    raw_red='test fixture::'+CASE+' ... FAILED\n'+raw_stages+record.replace('retained=true','retained=false')+f"thread 'case' panicked at {TEST}:{panic_line()}:5:\n"+MESSAGE+'\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    parsed=parse(raw_red);parsed['body_exit_code']=101;ensure(intended_red(parsed),'actual-format-red-parser')
    for raw in [raw_red+record,raw_red+raw_stages,raw_red.replace(MESSAGE,''),raw_red.replace(f':{panic_line()}:5:',f':{panic_line()+1}:5:'),raw_red+'thread x panicked at other.rs:1:1:\n',raw_red+'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n']:
        bad=parse(raw);bad['body_exit_code']=101;ensure(not intended_red(bad),'raw-parser-rejects-unqualified-red');negatives+=1
    return {'positive_controls':4,'negative_controls':negatives,'runtime_bodies':0}
