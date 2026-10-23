#!/usr/bin/env python3
"""Fresh directed component gates; ordinary BASE source, never a promotion gate."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import qualify_upstream_pure_command_offer as offer
import qualify_upstream_source_readiness_red as readiness
import qualify_upstream_source_readiness_candidate as ready_candidate
import pure_directed_snapshot_oracles as snapshot
import qualify_upstream_storage_app_handles as storage
from upstream_extraction_cohort import frozen_inputs

bounded=storage.old
ensure=bounded.ensure
SELF='scripts/qualify_upstream_pure_directed.py'
PINS='scripts/pure_directed_source_manifest.json'
ORACLES='scripts/pure_directed_snapshot_oracles.py'
OUT=Path('pure-directed-evidence')
COUNT_KEYS=('passed','failed','ignored','executed_nonignored')
STORAGE_FEATURES=['experimental-device-sync']
STATIC_FEATURES=sorted(['experimental-device-sync','extensions-draft','storage-format-benchmarks',
    'media-store-benchmarks','test-conformance-replay','test-migrated-template','test-support'])


def digest(data):return hashlib.sha256(data).hexdigest()
def identity(value):return digest(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
def safe_hash(path):
    try:return digest(path.read_bytes()) if path.is_file() and not path.is_symlink() else None
    except OSError:return None

def safe_mode(path):
    try:return stat.S_IMODE(path.stat().st_mode) if path.is_file() and not path.is_symlink() else None
    except OSError:return None

def binary_matches(path,phase):
    return safe_hash(path)==phase.get('binary_sha256') and safe_mode(path)==phase.get('binary_mode')

def fresh_write(path,data,mode):
    if path.is_symlink():path.unlink()
    previous=path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(data);path.chmod(mode)
    now=max(time.time_ns(),previous+1);os.utime(path,ns=(now,now))

def source_guard():
    manifest,guard=offer.source_guard()  # No historical guard/main and no module-global substitution.
    base=manifest['baseline'];owned=set(manifest['owned_metadata'])
    for name in [SELF,PINS,ORACLES]:
        ensure(name not in owned,'directed-files-must-be-ordinary-BASE-source')
        mode=subprocess.check_output(['git','ls-tree',base,'--',name],text=True).split()
        ensure(len(mode)==4 and mode[0]=='100644' and mode[1]=='blob','ordinary-directed-BASE-file-required')
        ensure(not Path(name).is_symlink() and not (Path(name).stat().st_mode & 0o111)
            and Path(name).read_bytes()==subprocess.check_output(['git','show',base+':'+name]),'directed-BASE-bytes-and-mode')
    pins=json.loads(Path(PINS).read_text())
    ensure(set(pins)=={'schema','source_authoring_reference','pinned_inputs','readiness_mutations','snapshot_mutations',
        'readiness_case','snapshot_cases','full19','static_features','oracle_sites','historical_evidence_reused'}
        and pins['schema']==1 and pins['historical_evidence_reused'] is False,'closed-directed-manifest')
    for name,sha in pins['pinned_inputs'].items():
        ensure(isinstance(name,str) and name.startswith(('scripts/','crates/')) and '..' not in Path(name).parts
            and isinstance(sha,str) and re.fullmatch('[0-9a-f]{64}',sha),'closed-pinned-input')
        ensure(not Path(name).is_symlink() and safe_hash(Path(name))==sha,'exact-directed-dependency:'+name)
    ensure(pins['readiness_mutations']==ready_candidate.MUTATIONS
        and pins['snapshot_mutations']==snapshot.MUTATIONS,'exact-reviewed-mutation-data')
    ensure(pins['readiness_case']==readiness.NAME and pins['snapshot_cases']==snapshot.CASES
        and pins['full19']==snapshot.FULL_NAMES and len(set(snapshot.FULL_NAMES))==19
        and pins['static_features']==STATIC_FEATURES,'fixed-directed-case-and-feature-inventory')
    ensure(readiness.assertion_line()==pins['oracle_sites']['readiness']==220
        and snapshot.CASES['round']['line']==pins['oracle_sites']['round']==789
        and snapshot.CASES['facts']['line']==pins['oracle_sites']['facts']==793
        and snapshot.UNWIND_LINE==pins['oracle_sites']['expected_unwind']==1673,'unchanged-exact-assertion-sites')
    for family in ['readiness_mutations','snapshot_mutations']:
        for spec in pins[family].values():
            ensure(set(spec)=={'path','old','new'} and spec['path'] in pins['pinned_inputs']
                and isinstance(spec['old'],str) and isinstance(spec['new'],str) and spec['old']!=spec['new']
                and Path(spec['path']).read_text().count(spec['old'])==1
                and spec['new'] not in Path(spec['path']).read_text(),'unique-exact-semantic-omission')
    return pins,guard


def require_qualified_baseline(phase,report):
    if phase.get('phase_passed') is not True:
        report['mutant_not_run_reason']='baseline-unqualified'
        report['restored_not_run_reason']='baseline-unqualified-no-mutation-attempt'
    ensure(phase.get('phase_passed') is True,'qualified-baseline-before-any-mutation-attempt')

def parser_controls():
    valid={'actual_counts_complete':True,'passed':1,'failed':0,'ignored':0,'executed_nonignored':1}
    ensure(complete(valid),'one-typed-body-count-positive')
    bad=[dict(valid,**{k:v}) for k,v in [('passed',True),('failed',False),('ignored',False),
        ('executed_nonignored',True),('actual_counts_complete',1),('passed',0),('failed',1),('ignored',1),('executed_nonignored',0)]]
    bad+=[{k:v for k,v in valid.items() if k!=key} for key in valid]
    for row in bad:ensure(not complete(row),'unknown-bool-or-inconsistent-counts-rejected')
    report={'phases':{'fixture':{'cases':{'ignored':{'test':'synthetic','actual_counts_complete':False,
        'passed':0,'failed':0,'ignored':1,'executed_nonignored':0}}}}}
    aggregate(report,1)
    ensure(report['actual_counts_complete'] and report['actual_ignored']==1 and report['actual_executed_nonignored']==0
        and not report['required_one_body_count_shapes_verified'] and not report['unknown_count_cases'],'observed-ignored-counts-preserved-not-qualified')
    report['phases']['fixture']['cases']['ignored'].pop('passed');aggregate(report,1)
    ensure(not report['actual_counts_complete'] and report['actual_passed'] is None
        and report['actual_ignored']==1 and report['known_partial_counts']['ignored']==1 and report['unknown_count_cases']==['synthetic'],'unknown-count-not-invented')
    qualified={}
    require_qualified_baseline({'phase_passed':True},qualified)
    ensure(not qualified,'qualified-baseline-allows-mutation-without-skip-label')
    for value in [False,None,1]:
        skipped={'mutation_attempted':False};rejected=False
        try:require_qualified_baseline({'phase_passed':value},skipped)
        except ValueError:rejected=True
        ensure(rejected and skipped['mutation_attempted'] is False
            and skipped.get('mutant_not_run_reason')=='baseline-unqualified'
            and skipped.get('restored_not_run_reason')=='baseline-unqualified-no-mutation-attempt','failed-baseline-not-retried-as-restored')
    return {'baseline_admission':{'positive':1,'negative':3},'typed_one_body_counts':{'positive':1,'negative':len(bad)},'observed_count_reporting':{'positive':2},'readiness':ready_candidate.parser_controls(),'snapshot':snapshot.parser_controls(),
        'full19_inventory':snapshot.full_inventory_controls(),'one_expected_caught_unwind':snapshot.expected_unwind_controls(),
        'actual_protocol_runtime_bodies':0,'historical_source_guard_invoked':False}


def complete(row):
    return (row.get('actual_counts_complete') is True and all(type(row.get(k)) is int for k in COUNT_KEYS)
        and row['passed']+row['failed']==row['executed_nonignored']==1 and row['ignored']==0)

def safe_compile_headers(compilation):
    # Header text can contain private payloads. Persist only closed codes and tracked source coordinates.
    text='\n'.join(compilation.pop('compiler_headers',[]))
    clean=re.sub(r'\x1b\[[0-9;]*m','',text)
    compilation['compiler_codes']=sorted(set(re.findall(r'(?m)^error\[(E[0-9]{4})\]:',clean)))[:32]
    tracked=set(frozen_inputs())
    sites=re.findall(r'(?m)^\s*--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)',clean)
    compilation['compiler_sites']=[{'file':p,'line':int(l),'column':int(c)} for p,l,c in sites if p in tracked][:32]


def cargo_events(raw,phase,expected,save):
    events=[];bad=0
    for line in raw.splitlines():
        if not line.startswith('{'):continue
        try:
            value=json.loads(line)
            if not isinstance(value,dict):bad+=1
            else:events.append(value)
        except (ValueError,TypeError):bad+=1
    errors=[v for v in events if v.get('reason')=='compiler-message' and isinstance(v.get('message'),dict)
        and v['message'].get('level')=='error']
    phase['compilation'].update(cargo_json_complete=bad==0,malformed_json_count=bad,compiler_error_count=len(errors),
        safe_errors=[bounded.safe_compiler_diagnostic(v,expected) for v in errors[:32]],errors_truncated=len(errors)>32)
    save();ensure(bad==0,'malformed-cargo-JSON-unqualified')
    return errors,[v for v in events if v.get('reason')=='compiler-artifact']


def compile_selected(mode,expected,phase,save):
    ensure(frozen_inputs()==expected,'before-compile-full-source-and-modes')
    if mode=='readiness':
        compilation,cases=readiness.compile_cases([readiness.CASE])
        safe_compile_headers(compilation);phase['compilation']=compilation;save()
        ensure(type(compilation.get('compile_exit_code')) is int and compilation['compile_exit_code']==0
            and type(compilation.get('compiler_error_count')) is int and compilation['compiler_error_count']==0
            and compilation.get('compiled_fingerprints',{}).get('verified') is True
            and set(cases)=={readiness.CASE} and cases[readiness.CASE]['name']==readiness.NAME,'one-six-feature-readiness-binary')
        phase['feature_identity']=readiness.feature_identity(compilation)
        ensure(set(phase['feature_identity']['nodes'])=={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'},'exact-six-compiled-dependency-nodes')
        binary=Path(cases[readiness.CASE]['binary'])
    else:
        command=['cargo','test','--locked','-p','storage-sqlite','--lib','--no-run','--message-format=json',
            '--features',','.join(STORAGE_FEATURES)]
        phase['compilation']={'command':command,'runtime_bodies':0,'succeeded':False};save()
        code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
        phase['compilation'].update(exit_code=code,wall_seconds=seconds);save()  # Save actual command result before JSON can reject.
        errors,artifacts=cargo_events(raw,phase,expected,save)
        selected=[v for v in artifacts if v.get('target',{}).get('name')=='storage_sqlite'
            and v['target'].get('kind')==['lib'] and v.get('profile',{}).get('test') is True and v.get('executable')]
        phase['compilation']['selected_test_artifact_count']=len(selected);save()
        ensure(type(code) is int and code==0 and not errors and len(selected)==1
            and sorted(selected[0]['features'])==STORAGE_FEATURES,'one-actual-experimental-storage-binary')
        feature_rows=sorted([{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],
            'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True))
        phase['feature_identity']={'selected_features':STORAGE_FEATURES,'artifact_feature_manifest_sha256':identity(feature_rows)}
        phase['compilation'].update(succeeded=True,compiled_features=STORAGE_FEATURES,
            compiler_artifact_feature_manifest_sha256=identity(feature_rows));binary=Path(selected[0]['executable'])
    phase['binary_sha256']=safe_hash(binary);phase['binary_mode']=safe_mode(binary);phase['source_manifest_sha256']=identity(expected);save()
    ensure(phase['binary_sha256'] is not None and frozen_inputs()==expected,'after-compile-source-binary')
    return binary


def exact_inventory(binary,name,phase,save):
    row={};phase.setdefault('inventory',{})[name]=row
    for ignored in [False,True]:
        code,raw,seconds=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60)
        parsed=storage.parse_inventory(raw,name,ignored)
        row['ignored' if ignored else 'normal']={'exit_code':code,'seconds':seconds,**parsed};save()
        ensure(type(code) is int and code==0 and parsed['passed'],'one-exact-nonignored-compiled-case')


def execute_one(binary,name,key,mode,label,mutation,expected,phase,save):
    exact_inventory(binary,name,phase,save)
    ensure(frozen_inputs()==expected and binary_matches(binary,phase),'before-body-source-binary')
    row={'test':name,'runtime_started':True,'actual_counts_complete':False,'component_oracle_passed':False}
    phase.setdefault('cases',{})[name]=row;save()
    try:
        code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        row.update(storage.parse_body(raw,code,name),seconds=seconds)
        row['numeric_summary_counts_observed']=all(type(row.get(k)) is int for k in ['passed','failed','ignored'])
        if row['numeric_summary_counts_observed']:row['executed_nonignored']=row['passed']+row['failed']
        save()
        # Persist physical source/binary evidence BEFORE a strict cause/oracle parser can raise.
        row.update(post_body_binary_sha256=safe_hash(binary),post_body_source_pristine=frozen_inputs()==expected)
        row['post_body_binary_mode']=safe_mode(binary)
        row['post_body_binary_pristine']=binary_matches(binary,phase);save()
        if mode=='readiness':
            value=readiness.parse(raw,code);row['typed_readiness']=value
            row['component_oracle_passed']=complete(row) and (readiness.intended_red(value) if label=='mutant' else ready_candidate.green(value))
        elif key in {'round','facts'}:
            row['closed_snapshot_facts']=snapshot.marker(raw,key)
            red=label=='mutant' and key==mutation
            row['component_oracle_passed']=(snapshot.intended_red(raw,code,key,row) if red else
                row['passed_gate'] and snapshot.marker_oracle(row['closed_snapshot_facts'],key,False))
        elif name==snapshot.UNWIND_NAME:
            row['expected_caught_unwind']=snapshot.expected_unwind(raw,code,name,row)
            row['component_oracle_passed']=row['expected_caught_unwind']['expected_caught_unwind_verified']
        else:row['component_oracle_passed']=row['passed_gate']
        row['component_oracle_passed']=bool(row['component_oracle_passed'] and complete(row)
            and row['post_body_source_pristine'] and row['post_body_binary_pristine'])
    except Exception as error:
        row.update(exception_type=type(error).__name__,component_oracle_passed=False)
        if isinstance(error,bounded.GateFailure):
            row.update(watchdog_triggered=str(error)=='bounded-command-timeout',output_limit_triggered=str(error)=='bounded-command-output-limit')
    finally:
        # Also preserve hash/source evidence for watchdog/parser/inventory failures; no raw output is saved.
        row['final_body_binary_sha256']=safe_hash(binary)
        try:row['final_body_source_pristine']=frozen_inputs()==expected
        except Exception:row['final_body_source_pristine']=False
        row['final_body_binary_mode']=safe_mode(binary)
        row['final_body_binary_pristine']=binary_matches(binary,phase)
        if not row['final_body_binary_pristine'] or not row['final_body_source_pristine']:row['component_oracle_passed']=False
        save()


def run_phase(mode,label,mutation,expected,phase,save):
    phase.update(cases={},phase_passed=False,source_manifest_sha256=identity(expected));save()
    binary=compile_selected(mode,expected,phase,save)
    if mode=='readiness':selected=[('readiness',readiness.NAME)]
    elif mode=='full19':selected=[({v['name']:k for k,v in snapshot.CASES.items()}.get(name,'control'),name) for name in snapshot.FULL_NAMES]
    else:selected=[(k,spec['name']) for k,spec in snapshot.CASES.items()]
    if mode=='full19':
        for ignored in [False,True]:
            code,raw,seconds=bounded.capture([str(binary),snapshot.MODULE]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60)
            value=snapshot.full_inventory(raw,ignored)
            phase.setdefault('module_inventory',{})['ignored' if ignored else 'normal']={'exit_code':code,'seconds':seconds,**value};save()
            ensure(type(code) is int and code==0 and value['passed'],'exact-seventeen-module-inventory')
    for key,name in selected:
        try:execute_one(binary,name,key,mode,label,mutation,expected,phase,save)
        except Exception as error:
            phase['cases'].setdefault(name,{'actual_counts_complete':False,'runtime_started':False}).update(
                exception_type=type(error).__name__,component_oracle_passed=False);save()
        # A failed body does not skip the remaining selected controls. Source drift blocks further execution.
        ensure(frozen_inputs()==expected and binary_matches(binary,phase),'phase-input-drift-stops-unsafe-next-body')
    phase.update(inputs_pristine=frozen_inputs()==expected,binary_pristine=binary_matches(binary,phase))
    phase['phase_passed']=(set(phase['cases'])=={name for _,name in selected}
        and all(row.get('component_oracle_passed') is True for row in phase['cases'].values())
        and phase['inputs_pristine'] and phase['binary_pristine']);save()
    return binary


def storage_static(expected,phase,save):
    command=['cargo','clippy','--locked','-p','storage-sqlite','--all-targets','--all-features','--message-format=json','--','-D','warnings']
    phase.update(compilation={'command':command,'runtime_bodies':0},static_passed=False,actual_executed_nonignored=0);save()
    ensure(frozen_inputs()==expected,'before-static-source')
    code,raw,seconds=bounded.capture(command,1800,limit=8*1024*1024)
    phase['compilation'].update(exit_code=code,wall_seconds=seconds);save()
    errors,artifacts=cargo_events(raw,phase,expected,save)
    own=[v for v in artifacts if v.get('target',{}).get('name')=='storage_sqlite' and v['target'].get('kind')==['lib']]
    phase['own_library_artifact_features']=[{'features':sorted(v['features']),'test_profile':v.get('profile',{}).get('test')} for v in own]
    phase['observed_artifact_feature_manifest_sha256']=identity(sorted([{'target':v['target']['name'],
        'kind':v['target']['kind'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True)))
    phase['expected_own_library_features']=STATIC_FEATURES
    phase['inputs_pristine']=frozen_inputs()==expected
    phase['static_passed']=(type(code) is int and code==0 and not errors and bool(own)
        and all(sorted(v['features'])==STATIC_FEATURES for v in own) and phase['inputs_pristine']);save()
    ensure(phase['static_passed'],'strict-all-targets-all-features-Storage-clippy')


def aggregate(report,required):
    rows=[row for phase in report['phases'].values() for row in phase.get('cases',{}).values()]
    field_known={k:len(rows)==required and all(type(row.get(k)) is int for row in rows) for k in COUNT_KEYS}
    report['actual_counts_complete']=all(field_known.values())
    report['actual_count_field_complete']=field_known
    report['required_one_body_count_shapes_verified']=len(rows)==required and all(complete(row) for row in rows)
    report['known_partial_counts']={k:sum(row[k] for row in rows if type(row.get(k)) is int) for k in COUNT_KEYS}
    for key in COUNT_KEYS:report['actual_'+key]=sum(row[key] for row in rows) if field_known[key] else None
    report['case_record_count']=len(rows)
    report['runtime_execution_attempt_count']=sum(row.get('runtime_started') is True for row in rows)
    report['unknown_count_cases']=[row['test'] for row in rows if not all(type(row.get(k)) is int for k in COUNT_KEYS) and 'test' in row]


def main(args):
    os.umask(0o077);OUT.mkdir(exist_ok=True)
    report={'mode':args.mode,'mutation':args.mutation,'phases':{},'preflight_passed':False,'component_mutation_qualified':False,
        'full19_component_passed':False,'storage_static_passed':False,'full_qualification':False,'native_acceptance_claim':False,
        'promotion_eligible':False,'historical_runtime_evidence_reused':False,'binary_fallback_used':False,'automatic_retries':0,
        'mutation_attempted':False}
    before=None;target=None;original=None;mode_bits=None;baseline_binary=None;baseline_sha=None;baseline_mode=None;backup=None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def attempt(label,expected):
        phase={};report['phases'][label]=phase;save()
        try:return run_phase(args.mode,label,args.mutation,expected,phase,save)
        except Exception as error:phase.update(exception_type=type(error).__name__,phase_passed=False);save();return None
    try:
        pins,report['source_guard']=source_guard();report['parser_controls']=parser_controls();save()
        if args.preflight:report['preflight_passed']=True;save();return
        ensure((args.mode=='readiness' and args.mutation in {'consume','permit'})
            or (args.mode=='snapshot' and args.mutation in {'round','facts'})
            or (args.mode in {'full19','storage-static'} and args.mutation is None),'closed-mode-mutation-pair')
        before=frozen_inputs();report['source_manifest_sha256']=identity(before)
        report['execution_cohort']={'stack_bytes':4194304,'cargo_build_jobs':2,'cargo_incremental':1,
            'readiness_Tokio_workers':2 if args.mode=='readiness' else None,'test_threads':1,
            'runtime_semantics':'unchanged multi-thread readiness case' if args.mode=='readiness' else ('zero runtime' if args.mode=='storage-static' else 'synchronous Storage cases'),
            'runtime_watchdog_seconds':None if args.mode=='storage-static' else 300,'runtime_output_limit_bytes':8*1024*1024}
        if args.mode=='storage-static':
            phase={};report['phases']['static']=phase;storage_static(before,phase,save)
            report['storage_static_passed']=True
        elif args.mode=='full19':
            baseline_binary=attempt('full19',before);baseline_sha=report['phases']['full19'].get('binary_sha256');baseline_mode=report['phases']['full19'].get('binary_mode')
            report['full19_component_passed']=report['phases']['full19'].get('phase_passed') is True
        else:
            spec=pins['readiness_mutations' if args.mode=='readiness' else 'snapshot_mutations'][args.mutation]
            target=Path(spec['path']);original=target.read_bytes();mode_bits=stat.S_IMODE(target.stat().st_mode)
            baseline_binary=attempt('baseline',before);baseline_sha=report['phases']['baseline'].get('binary_sha256');baseline_mode=report['phases']['baseline'].get('binary_mode')
            require_qualified_baseline(report['phases']['baseline'],report);save()
            if baseline_binary is not None:
                handle=tempfile.NamedTemporaryFile(prefix='pure-directed-baseline-',dir=os.environ.get('RUNNER_TEMP'),delete=False)
                backup=Path(handle.name);handle.close();shutil.copyfile(baseline_binary,backup)
            try:
                content=original.replace(spec['old'].encode(),spec['new'].encode(),1)
                report['mutation_attempted']=True;save()
                fresh_write(target,content,mode_bits);mutant=frozen_inputs()
                ensure(set(mutant)==set(before) and {p for p in before if mutant[p]!=before[p]}=={spec['path']}
                    and mutant[spec['path']]['mode']==before[spec['path']]['mode']
                    and mutant[spec['path']]['actual_executable']==before[spec['path']]['actual_executable']
                    and safe_hash(target)==digest(content),'only-reviewed-product-mutation')
                attempt('mutant',mutant)
            finally:
                # A mutant/setup/parser failure still gets a fresh actual restored compilation and body run.
                if target.is_symlink() or not target.is_file() or target.read_bytes()!=original or stat.S_IMODE(target.stat().st_mode)!=mode_bits:
                    fresh_write(target,original,mode_bits)
                else:
                    previous=target.stat().st_mtime_ns;now=max(time.time_ns(),previous+1);os.utime(target,ns=(now,now))
                ensure(frozen_inputs()==before,'exact-source-and-modes-before-restored-compile')
                attempt('restored',before)
            a,b,c=[report['phases'].get(k,{}) for k in ['baseline','mutant','restored']]
            report['component_mutation_qualified']=(all(v.get('phase_passed') is True for v in [a,b,c])
                and a.get('binary_sha256')==c.get('binary_sha256') and a.get('binary_sha256')!=b.get('binary_sha256')
                and a.get('binary_mode')==b.get('binary_mode')==c.get('binary_mode')
                and a.get('feature_identity')==b.get('feature_identity')==c.get('feature_identity')
                and a.get('source_manifest_sha256')==c.get('source_manifest_sha256'))
    except Exception as error:report['exception_type']=type(error).__name__
    finally:
        try:
            if target is not None and (target.is_symlink() or not target.is_file() or target.read_bytes()!=original or stat.S_IMODE(target.stat().st_mode)!=mode_bits):
                fresh_write(target,original,mode_bits)
            report['inputs_pristine']=frozen_inputs()==before if before is not None else None
        except Exception as error:report.update(inputs_pristine=False,restore_exception_type=type(error).__name__)
        if baseline_binary is not None:
            wanted=baseline_sha
            report['final_binary_sha256']=safe_hash(baseline_binary)
            report['final_binary_mode']=safe_mode(baseline_binary)
            report['final_binary_restored']=report['final_binary_sha256']==wanted and report['final_binary_mode']==baseline_mode
            if not report['final_binary_restored'] and backup is not None:
                report['binary_fallback_used']=True
                try:
                    if baseline_binary.is_symlink():baseline_binary.unlink()
                    shutil.copyfile(backup,baseline_binary);baseline_binary.chmod(baseline_mode)
                    report['final_binary_sha256']=safe_hash(baseline_binary)
                    report['final_binary_mode']=safe_mode(baseline_binary)
                    report['final_binary_restored']=report['final_binary_sha256']==wanted and report['final_binary_mode']==baseline_mode
                except Exception as error:report['binary_restore_exception_type']=type(error).__name__
        if backup is not None:
            try:backup.unlink()
            except OSError:pass
        required=0 if args.preflight or args.mode=='storage-static' else 19 if args.mode=='full19' else 3 if args.mode=='readiness' else 9
        aggregate(report,required)
        if report.get('inputs_pristine') is False or report['binary_fallback_used'] or report.get('final_binary_restored') is False:
            report['component_mutation_qualified']=report['full19_component_passed']=report['storage_static_passed']=False
        save()
    if args.preflight:ensure(report['preflight_passed'],'preflight-failed')
    else:
        gate='storage_static_passed' if args.mode=='storage-static' else 'full19_component_passed' if args.mode=='full19' else 'component_mutation_qualified'
        expected={'passed':2,'failed':1,'ignored':0,'executed_nonignored':3} if args.mode=='readiness' else (
            {'passed':8,'failed':1,'ignored':0,'executed_nonignored':9} if args.mode=='snapshot' else (
            {'passed':19,'failed':0,'ignored':0,'executed_nonignored':19} if args.mode=='full19' else
            {'passed':0,'failed':0,'ignored':0,'executed_nonignored':0}))
        ensure(report[gate] is True and report.get('inputs_pristine') is True and report['actual_counts_complete'] is True
            and all(type(report.get('actual_'+k)) is int and report['actual_'+k]==v for k,v in expected.items()),'fresh-directed-component-gate')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--preflight',action='store_true')
    p.add_argument('--mode',choices=['readiness','snapshot','full19','storage-static'],default='readiness')
    p.add_argument('--mutation',choices=['consume','permit','round','facts']);main(p.parse_args())
