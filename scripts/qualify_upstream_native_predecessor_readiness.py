#!/usr/bin/env python3
"""Prospective exact-predecessor readiness: fresh GREEN / gate omission RED / restored GREEN."""
import argparse, hashlib, json, os, re, shutil, stat, subprocess, time, sys, tempfile
from pathlib import Path
import qualify_upstream_storage_boundary as bounded
import qualify_upstream_storage_app_handles as counts
import upstream_completion_ci as completion
ensure=bounded.ensure
BASE='68c93c7b147fdce1911bb857f1b5b2982477ece9'
WORKFLOW_SHA='91a5415e2eda074fa46266ad04f6186859eff60b2de0170b4f0925f8c20a21ae'
SELF='scripts/qualify_upstream_native_predecessor_readiness.py'
WORKFLOW='.github/workflows/native-predecessor-readiness-pfp.yml'
REF='refs/heads/ci/upstream-native-predecessor-readiness-pfp-20261019'
PRODUCT='crates/marmot-app/src/client/device_linking/native_enrollment.rs'
PRODUCT_SHA='d44834916cb3102f840dc5b8775aab742284741aa2eeca3d772d032082c5cffe'
FIXTURE='crates/marmot-app/src/client/device_linking/setup/tests.rs'
FIXTURE_SHA='fbbf6412bf9a9d6ed036040913650326e55f455f4b1841c884d3dc7f7683e6c3'
COMPOSED='crates/marmot-app/src/tests.rs'
GATE='        if exact_predecessor {\n            return Ok(());\n        }\n'  # Reviewed prospective gate only; predicate/observation stay.
MUTANT_SHA='0601c1a2514d6f3e60466260e750d7ae51901ab8482f83cf9418631967bd02a2'
PRIOR_RED={'source': 'eeaac0739a9b593eed06ae99f60171586a5fd34e', 'run': 39178917369, 'genuine_RED': True, 'fixture_sha256': 'fbbf6412bf9a9d6ed036040913650326e55f455f4b1841c884d3dc7f7683e6c3', 'closed_receipt_sha256': '2282b0f0ee9414ba636cc3720dd2f7081529f7366d7dca658d8f82136f286960'}
EXPECTED_GRAPH={'marmot_app': ['default', 'experimental-device-sync', 'otlp-export', 'product-analytics-export', 'test-policy-overrides'], 'cgka_engine': ['default', 'experimental-device-sync', 'test-conformance-snapshot', 'test-crash-hooks', 'test-policy-overrides'], 'storage_sqlite': ['experimental-device-sync', 'storage-format-benchmarks', 'test-conformance-replay', 'test-migrated-template', 'test-support'], 'cgka_session': ['default', 'experimental-device-sync', 'test-policy-overrides'], 'marmot_account': ['experimental-device-sync'], 'transport_nostr': ['default', 'experimental-device-sync', 'test-policy-overrides', 'test-support']}
MESSAGE='live exact predecessor must wait without committing the new pairing policy'
NAME='client::device_linking::setup::tests::native_pair_sharing_waits_for_exact_predecessor_before_persistence'
FEATURES='marmot-app/otlp-export,marmot-uniffi/otlp-export,marmot-c/otlp-export,wn-cli/otlp-export,agent-connector/otlp-export,marmot-app/product-analytics-export,marmot-uniffi/product-analytics-export,marmot-c/product-analytics-export,wn-cli/product-analytics-export,agent-connector/product-analytics-export,wn-cli/test-policy-overrides,cgka-engine/test-policy-overrides,cgka-engine/test-crash-hooks,experimental-device-sync'
OUT=Path(os.environ.get('RUNNER_TEMP','/tmp'))/'native-predecessor-readiness-evidence'
NAMES=[NAME]
def digest(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args])
_OUTPUT_GIT_ROOT=None
def save(report):
    global _OUTPUT_GIT_ROOT
    if _OUTPUT_GIT_ROOT is None:_OUTPUT_GIT_ROOT=Path(git('rev-parse','--show-toplevel').decode().strip()).resolve()
    ensure(not within(OUT,_OUTPUT_GIT_ROOT),'output-must-remain-outside-checkout')
    OUT.mkdir(mode=0o700,exist_ok=True);(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
def layout(ref):
    result={}
    for item in git('ls-tree','-r','-z',ref).split(b'\0'):
        if item:
            meta,path=item.split(b'\t',1);mode,kind,sha=meta.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-whole-source-layout')
            result[os.fsdecode(path)]=(mode,sha)
    return result

def within(path,root):return path.resolve().is_relative_to(root.resolve())

def git_closure(mutant=False):
    changed=git('diff','--name-only','HEAD').decode().splitlines()
    untracked=git('ls-files','--others','--exclude-standard').splitlines()
    index_clean=subprocess.run(['git','diff','--cached','--quiet']).returncode==0
    quiet=subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
    return {'tracked_HEAD_pristine':quiet,'index_pristine':index_clean,'nonignored_untracked_count':len(untracked),
        'expected_tracked_change_only':set(changed)==({PRODUCT} if mutant else set()),
        'verified':index_clean and not untracked and (set(changed)=={PRODUCT} if mutant else quiet) and (_FINAL_ADMISSION is None or git('rev-parse','HEAD').decode().strip()==_FINAL_ADMISSION['head'])}

def source_matches(expected):return physical()==expected and git_closure(expected[PRODUCT][2]!=(_FINAL_ADMISSION['product_sha256'] if _FINAL_ADMISSION is not None else PRODUCT_SHA))['verified']

def without_fallback(report):return not report.get('fallback_source_restore_used',False) and not report.get('fallback_binary_copy_used',False)

def admitted_mutation_sequence(qualified,attempt,restore,fresh_restored):
    ensure(qualified is True,'PFP-baseline-must-qualify-before-mutation')
    try:attempt()
    finally:
        restore()
        fresh_restored()

def physical():
    rows={}
    for path,(mode,_) in layout('HEAD').items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode)
        ensure(link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode)),'physical-kind')
        ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        rows[path]=(mode,stat.S_IMODE(s.st_mode),digest(data))
    return rows

def source_guard(preflight=False,final_source=None):
    if final_source is not None:
        admission=final_source_guard(final_source)
        ensure(digest(Path(PRODUCT).read_bytes())==FINAL_PRODUCT_SHA
            and digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA
            and Path(PRODUCT).read_bytes().count(GATE.encode())==1
            and digest(Path(PRODUCT).read_bytes().replace(GATE.encode(),b'',1))==FINAL_MUTANT_SHA,'final-reviewed-product-and-sole-mutant')
        ensure(subprocess.run(['git','merge-base','--is-ancestor',PRIOR_RED['source'],final_source]).returncode==0
            and digest(git('show',PRIOR_RED['source']+':'+FIXTURE))==FIXTURE_SHA,'final-retains-genuine-prior-RED-fixture')
        admission.update(product_sha256=FINAL_PRODUCT_SHA,mutant_sha256=FINAL_MUTANT_SHA,fixture_sha256=FIXTURE_SHA)
        return admission
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE) and type(WORKFLOW_SHA) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA),'root-source-pins-required')
    ensure(Path.cwd().resolve()==Path(git('rev-parse','--show-toplevel').decode().strip()).resolve(),'physical-checkout-root')
    ensure(bool(os.environ.get('RUNNER_TEMP')) and Path(os.environ['RUNNER_TEMP']).is_dir()
        and not within(OUT,Path.cwd()),'hosted-output-outside-checkout')
    head=git('rev-parse','HEAD').decode().strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and (os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' or (preflight and os.environ.get('GITHUB_EVENT_NAME')=='push'))
        and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF
        and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_NATIVE_PREDECESSOR_READINESS_BASELINE')==BASE,'exact-hosted-ref-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-build-cohort')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',BASE,head]).returncode==0,'BASE-ancestor')
    baseline=layout(BASE);current=layout('HEAD')
    ensure(SELF not in baseline and WORKFLOW not in baseline and set(current)==set(baseline)|{SELF,WORKFLOW},'only-two-owned-metadata')
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'HEAD-pristine')
    for path,(mode,oid) in current.items():
        p=Path(path);s=p.lstat();link=stat.S_ISLNK(s.st_mode);expected=baseline.get(path,('100644',None))
        ensure(mode==expected[0] and link==(mode=='120000') and (link or stat.S_ISREG(s.st_mode))
            and (link or bool(s.st_mode&0o111)==(mode=='100755')),'whole-source-modes')
        ensure(within(p,Path.cwd()),'every-tracked-path-within-checkout')
        data=os.fsencode(os.readlink(p)) if link else p.read_bytes()
        actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        ensure(actual==oid and (expected[1] is None or actual==expected[1]),'whole-BASE-and-HEAD-content')
    ensure(digest(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA and digest(Path(PRODUCT).read_bytes())==PRODUCT_SHA
        and digest(Path(FIXTURE).read_bytes())==FIXTURE_SHA
        and type(GATE) is str and GATE and Path(PRODUCT).read_bytes().count(GATE.encode())==1
        and type(MUTANT_SHA) is str and re.fullmatch('[0-9a-f]{64}',MUTANT_SHA)
        and digest(Path(PRODUCT).read_bytes().replace(GATE.encode(),b'',1))==MUTANT_SHA,'exact-workflow-and-product-witness')
    ensure(type(PRIOR_RED) is dict and PRIOR_RED.get('genuine_RED') is True and PRIOR_RED.get('fixture_sha256')==FIXTURE_SHA
        and type(PRIOR_RED.get('source')) is str and re.fullmatch('[0-9a-f]{40}',PRIOR_RED['source'])
        and type(PRIOR_RED.get('closed_receipt_sha256')) is str and re.fullmatch('[0-9a-f]{64}',PRIOR_RED['closed_receipt_sha256']),'reviewed-prior-RED-required')
    ensure(subprocess.run(['git','merge-base','--is-ancestor',PRIOR_RED['source'],BASE]).returncode==0
        and digest(git('show',PRIOR_RED['source']+':'+FIXTURE))==FIXTURE_SHA,'historical-receipt-source-and-unchanged-fixture')
    ensure(type(EXPECTED_GRAPH) is dict and set(EXPECTED_GRAPH)=={'marmot_app','cgka_engine','storage_sqlite','cgka_session','marmot_account','transport_nostr'}
        and all(type(v) is list and all(type(x) is str for x in v) for v in EXPECTED_GRAPH.values()),'reviewed-exact-feature-contract-required')
    ensure(git_closure()['verified'],'tracked-index-and-untracked-admission-closure')
    return {'head':head,'baseline':BASE,'whole_source_modes_verified':True,'Rust_exceptions':[],
        'old_guards_or_main_called':False,'old_module_globals_mutated':False,'historical_runtime_reused':False}


FINAL_PRODUCT_SHA='c57a40e65edf5802614bf8759a2c6b1f36715e9033753c8941db3293a8a8ca93'
FINAL_MUTANT_SHA='c3a0e05b5c88c83c8b487f3c9f255fe61cad8745d41e23b5b7cc4e50f4db75c5'
_FINAL_ADMISSION=None

# Explicit final-source mode: this pair alone may overlay the immutable source.
FINAL_SOURCE_FLOOR='1497415b4712c63ce56b60934089c535333a03f1'
FINAL_REF_PATTERN=r'refs/heads/ci/upstream-develop-dy-[a-z0-9][a-z0-9-]{0,119}'

def _final_git(*args):return subprocess.check_output(['git',*args])
def _final_layout(ref):
    result={}
    for item in _final_git('ls-tree','-rz',ref).split(b'\0'):
        if not item:continue
        meta,path=item.split(b'\t',1);mode,kind,oid=meta.decode().split();path=os.fsdecode(path)
        ensure(kind=='blob' and mode in {'100644','100755','120000'},'final-ordinary-layout')
        ensure(not Path(path).is_absolute() and '..' not in Path(path).parts,'final-relative-path')
        result[path]=(mode,oid)
    return result

def _final_physical(current):
    root=Path.cwd();rows={}
    ensure(root.resolve()==Path(_final_git('rev-parse','--show-toplevel').decode().strip()).resolve(),'final-physical-root')
    for name,(mode,_) in current.items():
        path=Path(name);parent=path.parent
        while parent!=Path('.'):
            s=parent.lstat();ensure(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode),'final-parent-not-link')
            parent=parent.parent
        s=path.lstat()
        ensure((mode=='120000' and stat.S_ISLNK(s.st_mode)) or
               (mode!='120000' and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==(0o755 if mode=='100755' else 0o644)), 'final-physical-mode')
        data=os.fsencode(os.readlink(path)) if mode=='120000' else path.read_bytes()
        oid=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        rows[name]=(mode,oid)
    return rows

def _final_admission_check(source,head,env,baseline,current,physical,ancestor,floor,index_clean,untracked):
    ensure(type(source) is str and re.fullmatch('[0-9a-f]{40}',source) and
           type(head) is str and re.fullmatch('[0-9a-f]{40}',head),'final-full-commit-input')
    ref=env.get('GITHUB_REF','')
    ensure(env.get('GITHUB_ACTIONS')=='true' and env.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
           and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and re.fullmatch(FINAL_REF_PATTERN,ref)
           and env.get('GITHUB_SHA')==head and env.get('GITHUB_WORKFLOW_SHA')==head
           and env.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+ref,'final-exact-manual-workflow')
    ensure(ancestor is True and floor is True,'final-reviewed-source-ancestor')
    owned={SELF,WORKFLOW}
    ensure(set(baseline)==set(current) and owned<=set(current),'final-exact-path-inventory')
    for path,(mode,oid) in current.items():
        ensure(mode in {'100644','100755','120000'} and re.fullmatch('[0-9a-f]{40}',oid),'final-Git-mode-object')
        ensure(mode=='100644' if path in owned else (mode,oid)==baseline[path],'final-only-own-two-metadata')
    ensure(physical==current and index_clean is True and not untracked,'final-physical-index-untracked')
    return True

def final_source_guard(source):
    head=_final_git('rev-parse','HEAD').decode().strip()
    ensure(type(source) is str and re.fullmatch('[0-9a-f]{40}',source),'final-full-commit-input')
    ensure(_final_git('rev-parse',source+'^{commit}').decode().strip()==source,'final-exact-commit-object')
    baseline=_final_layout(source);current=_final_layout('HEAD')
    allowed={str(OUT/'result.json')} if not Path(OUT).is_absolute() else set()
    untracked={os.fsdecode(path) for path in _final_git('ls-files','--others','--exclude-standard','-z').split(b'\0') if path}
    _final_admission_check(source,head,dict(os.environ),baseline,current,_final_physical(current),
        subprocess.run(['git','merge-base','--is-ancestor',source,head]).returncode==0,
        subprocess.run(['git','merge-base','--is-ancestor',FINAL_SOURCE_FLOOR,source]).returncode==0,
        subprocess.run(['git','diff','--cached','--quiet','HEAD']).returncode==0,untracked-allowed)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'final-whole-HEAD-pristine')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
           and os.environ.get('RUST_MIN_STACK')=='4194304'
           and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
               'RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL'])
           and not any(value for key,value in os.environ.items() if re.fullmatch(r'CARGO_TARGET_.+_RUSTFLAGS',key)), 'final-exact-build-profile')
    return {'mode':'explicit-final-source','head':head,'source':source,'source_tree':_final_git('rev-parse',source+'^{tree}').decode().strip(),
        'workflow_sha':os.environ['GITHUB_WORKFLOW_SHA'],'own_metadata_only':sorted({SELF,WORKFLOW}),
        'workflow_Git_blob':current[WORKFLOW][1],'helper_Git_blob':current[SELF][1],
        'whole_source_modes_verified':True,'Rust_exceptions':[],'historical_runtime_reused':False}

def final_admission_close(report,probe):
    try:accepted=probe() is True
    except Exception as error:
        accepted=False;report['final_admission_error_type']=type(error).__name__
    report['final_source_admission_exact']=accepted
    if not accepted:
        for key in ['qualified','component_PFP_verified','expected_outcome_verified']:report[key]=False
    return accepted

def final_admission_controls():
    # Pure metadata runs on the remote worker. Exercise the exact admission check.
    f='1'*40;t='2'*40;ref='refs/heads/ci/upstream-develop-dy-final-controls-20261019'
    env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'dyKiU/mdk','GITHUB_EVENT_NAME':'workflow_dispatch',
         'GITHUB_REF':ref,'GITHUB_SHA':t,'GITHUB_WORKFLOW_SHA':t,'GITHUB_WORKFLOW_REF':'dyKiU/mdk/'+WORKFLOW+'@'+ref}
    base={SELF:('100644','a'*40),WORKFLOW:('100644','b'*40),'product.rs':('100644','c'*40),
          'Cargo.lock':('100644','d'*40),'.cargo/config.toml':('100644','e'*40),'foreign.yml':('100644','f'*40)}
    peer_helper=('scripts/qualify_upstream_native_predecessor_readiness.py' if SELF.endswith('qualify_options_composition.py') else 'scripts/qualify_options_composition.py')
    peer_workflow=('.github/workflows/native-predecessor-readiness-pfp.yml' if WORKFLOW.endswith('options-composition-pfp.yml') else '.github/workflows/options-composition-pfp.yml')
    base[peer_helper]=('100644','6'*40);base[peer_workflow]=('100644','7'*40)
    current=dict(base);current[SELF]=('100644','0'*40);current[WORKFLOW]=('100644','3'*40)
    def check(source=f,head=t,environment=None,before=None,after=None,physical=None,ancestor=True,floor=True,index=True,untracked=()):
        selected=current if after is None else after
        return _final_admission_check(source,head,env if environment is None else environment,base if before is None else before,
            selected,selected if physical is None else physical,ancestor,floor,index,untracked)
    ensure(check(),'final-owned-metadata-positive')
    ensure(check(source=t,before=current),'final-source-equals-tool-head-positive')
    negatives=[]
    for key,value in [('GITHUB_ACTIONS','false'),('GITHUB_REPOSITORY','foreign/mdk'),('GITHUB_EVENT_NAME','push'),
                      ('GITHUB_REF','refs/heads/master'),('GITHUB_WORKFLOW_SHA',f),('GITHUB_SHA',f),('GITHUB_WORKFLOW_REF','foreign')]:
        changed=dict(env);changed[key]=value;negatives.append({'environment':changed})
    negatives += [{'source':'1'*39},{'source':'A'*40},{'head':'2'*39},{'ancestor':False},{'floor':False},{'index':False},{'untracked':['extra.rs']}]
    for path in ['product.rs','Cargo.lock','.cargo/config.toml','foreign.yml',peer_helper,peer_workflow]:
        changed=dict(current);changed[path]=('100644','4'*40);negatives.append({'after':changed})
    for changed in [dict(current,extra=('100644','5'*40)),{k:v for k,v in current.items() if k!='product.rs'},
                    dict(current,**{SELF:('100755','0'*40)}),dict(current,**{WORKFLOW:('120000','3'*40)})]:
        negatives.append({'after':changed})
    wrong=dict(current);wrong['product.rs']=('100644','4'*40);negatives.append({'physical':wrong})
    for values in negatives:
        try:check(**values);accepted=True
        except ValueError:accepted=False
        ensure(not accepted,'final-source-adversary-rejected')
    saved={'qualified':True,'component_PFP_verified':True,'expected_outcome_verified':True,'actual_body_count':3}
    ensure(final_admission_close(saved,lambda:True) and saved['qualified'],'final-closure-positive')
    def throwing():raise FileNotFoundError('synthetic')
    for probe in [lambda:False,throwing]:
        failed=dict(saved);ensure(not final_admission_close(failed,probe) and failed['actual_body_count']==3
            and all(failed[key] is False for key in ['qualified','component_PFP_verified','expected_outcome_verified']), 'final-closure-failure-retains-counts-no-credit')
    return {'positive':2,'negative':len(negatives),'closure_positive':1,'closure_negative':2,'metadata_only':True,'actual_product_bodies':0}

def clean(raw):return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',raw)
FLAGS=['exact','live','primary','pending','no_policy','successor_policies','storage_closed','native_denial','waiting_ok']
def expected_sites():
    source=Path(FIXTURE).read_text();ensure(source.count(MESSAGE)==1,'unique-final-waiting-oracle')
    start=source.rfind('assert!(',0,source.index(MESSAGE));ensure(start>=0,'source-owned-final-assertion')
    own=(FIXTURE,source[:start].count('\n')+1,len(source[:start].rsplit('\n',1)[-1])+1)
    rows=Path(COMPOSED).read_text().splitlines();hits=[i for i,line in enumerate(rows) if 'test_thread.join().unwrap();' in line]
    ensure(len(hits)==1,'unique-composed-join-wrapper')
    i=hits[0];return own,(COMPOSED,i+1,rows[i].index('unwrap()')+1)

def verdict(raw,code,basic,expected):
    text=clean(raw);header=r'(?m)^test '+re.escape(NAME)+r' \.\.\. '
    ensure(len(re.findall(header,text))==1,'one-genuine-exact-libtest-header')
    text=re.sub(header,lambda hit:hit[0]+'\n',text,count=1)
    lines=[line for line in text.splitlines() if 'native-predecessor-readiness ' in line]
    ensure(len(lines)==1 and len(lines[0].encode())<=1024,'unique-bounded-closed-readiness-marker')
    pattern='native-predecessor-readiness '+' '.join(key+'=(true|false)' for key in FLAGS[:6])+' shutdown_returns=3 '+' '.join(key+'=(true|false)' for key in FLAGS[6:])
    hit=re.fullmatch(pattern,lines[0]);ensure(hit is not None,'strict-readiness-marker')
    flags=dict(zip(FLAGS,[v=='true' for v in hit.groups()]))
    prerequisites=all(flags[k] for k in ['exact','live','pending','no_policy','successor_policies','storage_closed']) and not flags['primary']
    own,wrapper=expected_sites()
    panics=re.findall(r"(?m)^thread '([^'\n]+)'(?: \([1-9][0-9]{0,9}\))? panicked at ([A-Za-z0-9_./-]+):([0-9]+):([0-9]+):\n([^\n]*)",text)
    exact=[('native-predecessor-readiness',own[0],str(own[1]),str(own[2]),MESSAGE),
        (NAME,wrapper[0],str(wrapper[1]),str(wrapper[2]),'called `Result::unwrap()` on an `Err` value: Any { .. }')]
    sole=panics==exact and text.count('panicked at ')==2
    complete=(basic.get('actual_counts_complete') is True and basic.get('executed_nonignored')==1 and basic.get('ignored')==0 and basic.get('compiler_error_count')==0)
    green=complete and basic.get('passed_gate') is True and prerequisites and flags['waiting_ok'] and not flags['native_denial'] and not panics
    red=complete and type(code)is int and code==101 and basic.get('passed')==0 and basic.get('failed')==1 and basic.get('panic_count')==2 and prerequisites and not flags['waiting_ok'] and flags['native_denial'] and sole
    return {'observed':flags,'actual_shutdown_returns':3,'all_genuine_prerequisites':bool(prerequisites),'sole_final_named_assertion_and_composed_wrapper':sole,
        'focused_GREEN':bool(green),'genuine_behavioral_RED':bool(red),'expected_outcome_verified':bool(red if expected=='red' else green),'raw_identity_or_error_exported':False}

def compile_app(report,cohort,tracked,save_report):
    features=['otlp-export','product-analytics-export','test-policy-overrides','experimental-device-sync']
    command=['cargo','test','--locked','--workspace','--no-run','--message-format=json']
    if features:command+=['--features',FEATURES]
    code,raw,seconds=bounded.capture(command,3600,limit=8*1024*1024)
    events=[];malformed=0
    for line in raw.splitlines():
        if line.startswith('{'):
            try:events.append(json.loads(line))
            except ValueError:malformed+=1
    finished=[v for v in events if v.get('reason')=='build-finished']
    complete=len(finished)==1 and finished[0].get('success') is True and malformed==0
    errors=[v for v in events if v.get('reason')=='compiler-message' and v.get('message',{}).get('level')=='error']
    artifacts=[v for v in events if v.get('reason')=='compiler-artifact']
    selected=[v for v in artifacts if v.get('target',{}).get('name')=='marmot_app' and v['target'].get('kind')==['lib'] and v.get('profile',{}).get('test') is True and v.get('executable')]
    codes=sorted({v.get('message',{}).get('code',{}).get('code') for v in errors if type(v.get('message',{}).get('code')) is dict and re.fullmatch(r'E[0-9]{4}',v['message']['code'].get('code',''))})
    sites=[{'file':s['file_name'],'line':s['line_start'],'column':s['column_start']} for v in errors for s in v.get('message',{}).get('spans',[]) if s.get('file_name') in tracked and s.get('is_primary') is True]
    report['compilation']={'command':command,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors) if finished else None,'build_finished_success':complete,'malformed_JSON_lines':malformed,'compiler_codes':codes[:32],
        'compiler_sites':sites[:32],'closed_diagnostics_truncated':len(codes)>32 or len(sites)>32,'selected_test_artifact_count':len(selected),'features_requested':features};save_report()
    ensure(type(code) is int and code==0 and complete and not errors and len(selected)==1,'one-successful-App-lib-compilation')
    artifact=selected[0];observed=artifact.get('features')
    ensure(type(observed) is list and all(type(v) is str for v in observed) and len(observed)==len(set(observed)) and set(observed)==set(features)|{'default'} and artifact.get('fresh') is False,'actual-App-unit-feature-cohort')
    binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink() and re.fullmatch(r'marmot_app-[0-9a-f]{16}',binary.name) and binary.resolve().is_relative_to(Path(os.environ.get('CARGO_TARGET_DIR','target')).resolve()),'regular-App-test-binary')
    report['compiled_features']={'observed_own_unit_features':sorted(observed),'actual_test_profile':True,'fresh_App_artifact_required':True,'observed_App_artifact_fresh':artifact.get('fresh'),'all_Cargo_artifact_feature_manifest_sha256':digest(json.dumps(sorted([{'package':v['package_id'],'target':v['target']['name'],'kind':v['target']['kind'],'features':sorted(v['features']),'profile':v['profile']} for v in artifacts],key=lambda v:json.dumps(v,sort_keys=True)),sort_keys=True).encode()),'all_emitted_compiler_artifact_feature_cohort_recorded':True,'all_dependencies_freshly_built_claimed':False};save_report()
    graph=completion.feature_metadata(binary)
    report['dependency_fingerprints']=graph;save_report()
    ensure(graph.get('verified') is True and {k:sorted(v['features']) for k,v in graph.get('nodes',{}).items()}=={k:sorted(v) for k,v in EXPECTED_GRAPH.items()},'actual-exact-reviewed-six-node-feature-graph')
    return binary

def aggregate(cases,expected_count):
    result={'actual_case_rows':len(cases),'expected_case_rows':expected_count,'unknown_count_cases':sum(any(type(row.get('basic_counts',{}).get(k)) is not int for k in ['passed','failed','ignored','executed_nonignored']) for row in cases),'nonqualifying_count_shape_cases':sum(row.get('basic_counts',{}).get('actual_counts_complete') is not True for row in cases),'missing_case_rows':max(0,expected_count-len(cases))}
    for key in ['passed','failed','ignored','executed_nonignored']:
        values=[row.get('basic_counts',{}).get(key) for row in cases]
        known=[v for v in values if type(v) is int and v>=0]
        result['actual_'+key]=sum(values) if len(cases)==expected_count and len(known)==len(values) else None
        result['known_partial_'+key]=sum(known) if known else None
    return result

def execute_case(root,row,binary,before,mode,parent,expected_inputs,name,expected):
    row.update(name=name,expected=expected,runtime_attempted=False,actual_executed_nonignored=0,expected_outcome_verified=False)
    save(root)
    for ignored in [False,True]:
        code,text,_=bounded.capture([str(binary),'--exact',name]+(['--ignored'] if ignored else [])+['--list','--format','terse'],60,limit=1024*1024)
        item=counts.parse_inventory(text,name,ignored);row.setdefault('inventory',{})['ignored' if ignored else 'normal']=item;save(root)
        ensure(code==0 and item['passed'],'one-normal-zero-ignored-exact-case')
    ensure(source_matches(expected_inputs) and binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode,'prebody-source-binary-mode')
    row.update(runtime_attempted=True,actual_executed_nonignored=None);save(root)
    try:code,raw,seconds=bounded.capture([str(binary),'--exact',name,'--nocapture','--test-threads=1'],900,limit=8*1024*1024)
    except bounded.GateFailure as error:
        row['watchdog_triggered']=str(error)=='bounded-command-timeout';row['output_limit_triggered']=str(error)=='bounded-command-output-limit';save(root);raise
    row.update(body_exit_code=code,body_seconds=seconds,source_after_body_pristine=source_matches(expected_inputs),
        binary_after_sha256=digest(binary.read_bytes()) if binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() else None,
        binary_after_mode=stat.S_IMODE(binary.stat().st_mode) if binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() else None);save(root)
    basic=counts.parse_body(raw,code,name);row['basic_counts']=basic
    for dest,key in [('actual_passed','passed'),('actual_failed','failed'),('actual_ignored','ignored'),('actual_executed_nonignored','executed_nonignored')]:row[dest]=basic.get(key)
    row['actual_test_passed']=basic.get('passed_gate') is True;save(root)
    ensure(row['source_after_body_pristine'] and row['binary_after_sha256']==before and row['binary_after_mode']==mode,'postbody-source-binary-mode')
    row['outcome']=verdict(raw,code,basic,expected);row['expected_outcome_verified']=row['outcome']['expected_outcome_verified'];save(root)

def phase(root,label,cohort,expected_inputs,specs,different_from=None):
    row={'cases':[],'phase_passed':False,'expected_case_count':len(specs)};root.setdefault('phases',{})[label]=row;save(root)
    ensure(source_matches(expected_inputs),'phase-before-compile-pristine')
    row['free_bytes_before_compile']=shutil.disk_usage('.').free
    row['capacity_reserve_satisfied']=row['free_bytes_before_compile']>=8*1024**3
    if not row['capacity_reserve_satisfied']:row['compile_admission_failure']='insufficient_disk_reserve'
    save(root);ensure(row['capacity_reserve_satisfied'],'phase-disk-reserve-before-build')
    row['fresh_App_source_mtimes']=[]
    for refresh in [Path(PRODUCT),Path(FIXTURE)]:
        ensure(refresh.is_file() and not refresh.is_symlink(),'fresh-compile-source-kind')
        approved_parent(refresh,Path.cwd().resolve()/refresh.parent)
        old=refresh.stat().st_mtime_ns;stamp=max(time.time_ns(),old+2_000_000_000);os.utime(refresh,ns=(stamp,stamp))
        after=refresh.stat().st_mtime_ns
        row['fresh_App_source_mtimes'].append({'path':str(refresh),'before_ns':old,'requested_ns':stamp,'actual_after_ns':after});save(root)
        ensure(after>old,'actual-source-mtime-advanced')
    row['fresh_App_method']='mtime-only-reviewed-product-and-fixture';save(root)
    binary=compile_app(row,cohort,set(expected_inputs),lambda:save(root))
    parent=binary.parent.resolve();before=digest(binary.read_bytes());mode=stat.S_IMODE(binary.stat().st_mode);row['binary_before']={'sha256':before,'mode':mode};save(root)
    ensure(source_matches(expected_inputs),'phase-after-compile-pristine')
    if different_from is not None:ensure(before!=different_from,'mutant-binary-must-differ-before-runtime')
    for name,expected in specs:
        case={};row['cases'].append(case);save(root)
        try:execute_case(root,case,binary,before,mode,parent,expected_inputs,name,expected)
        except Exception as error:case['controller_failure_type']=type(error).__name__;save(root)
    row.update(aggregate(row['cases'],len(specs)))
    row['source_after_phase_pristine']=source_matches(expected_inputs)
    row['binary_after_phase_pristine']=binary.parent.resolve()==parent and binary.is_file() and not binary.is_symlink() and digest(binary.read_bytes())==before and stat.S_IMODE(binary.stat().st_mode)==mode
    row['phase_passed']=row['source_after_phase_pristine'] and row['binary_after_phase_pristine'] and len(row['cases'])==len(specs) and all(case.get('expected_outcome_verified') is True for case in row['cases'])
    save(root);return binary,before,mode,parent

def omitted_gate(data,gate,wanted):
    ensure(type(gate) is str and gate and data.count(gate.encode())==1,'unique-only-waiting-return-block')
    result=data.replace(gate.encode(),b'',1)
    ensure(digest(result)==wanted,'full-omission-product-hash')
    return result

def approved_parent(path,parent):
    ensure(isinstance(parent,Path),'approved-original-parent-required')
    ensure(path.parent.resolve()==parent and path.parent.is_dir(),'owned-parent-resolution-unchanged')

def write_fresh(path,data,mode,parent):
    approved_parent(path,parent)
    ensure(not path.is_symlink(),'owned-write-refuses-leaf-symlink')
    previous=path.stat().st_mtime_ns if path.exists() else 0
    path.write_bytes(data);path.chmod(mode)
    timestamp=max(time.time_ns(),previous+2_000_000_000);os.utime(path,ns=(timestamp,timestamp))

def restore_owned(path,data,mode,parent):
    approved_parent(path,parent)
    if path.is_symlink():path.unlink()
    ensure(not path.exists() or path.is_file(),'owned-restore-file-kind')
    write_fresh(path,data,mode,parent)

def runtime(report,cohort,expected):
    frozen=physical();product=Path(PRODUCT);original=product.read_bytes();product_mode=stat.S_IMODE(product.stat().st_mode)
    product_parent=Path.cwd().resolve()/product.parent
    approved_parent(product,product_parent);ensure(within(product,Path.cwd()),'owned-product-in-checkout')
    baseline_binary=None;baseline_bytes=None;baseline_mode=None;baseline_hash=None;baseline_parent=None;mutation_attempted=False
    report.update(runtime_attempted=False,mutation_attempted=False,component_PFP_verified=False,fallback_source_restore_used=False,fallback_binary_copy_used=False)
    try:
        free=shutil.disk_usage('.').free;report['free_bytes']=free;save(report);ensure(free>=8*1024**3,'remote-disk-reserve')
        specs=[(name,'green') for name in NAMES]
        baseline_binary,baseline_hash,baseline_mode,baseline_parent=phase(report,'baseline',cohort,frozen,specs)
        ensure(baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink()
            and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode,'baseline-backup-only-admitted-regular-binary')
        baseline_bytes=baseline_binary.read_bytes();report['runtime_attempted']=any(row.get('runtime_attempted') for row in report['phases']['baseline']['cases'])
        if expected=='green':
            report['expected_outcome_verified']=report['phases']['baseline']['phase_passed'];save(report)
            ensure(report['expected_outcome_verified'],'required-baseline-outcome-not-established');return
        # Admission is before mutation/finally: an unqualified baseline is not retried as restoration.
        if report['phases']['baseline']['phase_passed'] is not True:
            report['skipped_mutant_and_restored_reason']='baseline_unqualified_no_mutation_attempted';save(report)
            raise ValueError('PFP-baseline-must-qualify-before-mutation')
        product_sha=report['source_guard'].get('product_sha256',PRODUCT_SHA);mutant_sha=report['source_guard'].get('mutant_sha256',MUTANT_SHA)
        ensure(digest(original)==product_sha and type(GATE) is str and original.count(GATE.encode())==1,'exact-fixed-product-before-mutation')
        mutant=omitted_gate(original,GATE,mutant_sha)
        ensure(digest(mutant)==mutant_sha,'exact-reviewed-waiting-return-only-mutant')
        expected_mutant=dict(frozen);expected_mutant[PRODUCT]=(frozen[PRODUCT][0],product_mode,digest(mutant))
        def attempt():
            nonlocal mutation_attempted
            try:
                mutation_attempted=True;report['mutation_attempted']=True;save(report)
                write_fresh(product,mutant,product_mode,product_parent)
                ensure(source_matches(expected_mutant),'only-owned-waiting-return-source-and-mode')
                phase(report,'mutant',cohort,expected_mutant,[(NAME,'red')],different_from=baseline_hash)
            except Exception as error:report['mutant_controller_failure_type']=type(error).__name__;save(report)
        def restore():
            restore_owned(product,original,product_mode,product_parent)
            report['source_restored_before_fresh_compile']=source_matches(frozen);save(report)
            ensure(report['source_restored_before_fresh_compile'],'exact-source-restore-before-compile')
        def fresh_restored():
            try:phase(report,'restored',cohort,frozen,[(name,'green') for name in NAMES])
            except Exception as error:report['restored_controller_failure_type']=type(error).__name__;save(report)
        admitted_mutation_sequence(report['phases']['baseline']['phase_passed'],attempt,restore,fresh_restored)
        rows=[case for label in ['baseline','mutant','restored'] for case in report.get('phases',{}).get(label,{}).get('cases',[])]
        report['aggregate']=aggregate(rows,3)
        restored=report.get('phases',{}).get('restored',{});mutant_row=report.get('phases',{}).get('mutant',{})
        report['baseline_restored_binary_equal']=restored.get('binary_before')==report['phases']['baseline']['binary_before']
        signatures=[{name:node['features'] for name,node in report['phases'].get(label,{}).get('dependency_fingerprints',{}).get('nodes',{}).items()} for label in ['baseline','mutant','restored']]
        report['same_observed_dependency_feature_cohort']=bool(signatures[0] and signatures[0]==signatures[1]==signatures[2])
        allfeatures=[report['phases'].get(label,{}).get('compiled_features',{}).get('all_Cargo_artifact_feature_manifest_sha256') for label in ['baseline','mutant','restored']]
        report['same_all_emitted_compiler_artifact_features']=bool(allfeatures[0] and allfeatures[0]==allfeatures[1]==allfeatures[2])
        report['git_closure_before_PFP']=git_closure();save(report)
        report['component_PFP_verified']=(report['git_closure_before_PFP']['verified'] and without_fallback(report) and all(report.get('phases',{}).get(label,{}).get('phase_passed') is True for label in ['baseline','mutant','restored'])
            and report['aggregate'].get('actual_passed')==2 and report['aggregate'].get('actual_failed')==1 and report['aggregate'].get('actual_ignored')==0
            and report['aggregate'].get('actual_executed_nonignored')==3 and report['baseline_restored_binary_equal'] and report['same_observed_dependency_feature_cohort'] and report['same_all_emitted_compiler_artifact_features']
            and mutant_row.get('binary_before',{}).get('sha256')!=baseline_hash)
        report['expected_outcome_verified']=report['component_PFP_verified'];save(report);ensure(report['component_PFP_verified'],'fresh-three-body-PFP-required')
    finally:
        if product.is_symlink() or not product.is_file() or product.read_bytes()!=original or stat.S_IMODE(product.stat().st_mode)!=product_mode:
            report['fallback_source_restore_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
            restore_owned(product,original,product_mode,product_parent)
        report['final_git_closure']=git_closure()
        report['final_HEAD_git_pristine']=report['final_git_closure']['tracked_HEAD_pristine']
        report['source_final_pristine']=physical()==frozen and report['final_git_closure']['verified']
        if baseline_binary is not None and baseline_bytes is not None:
            good=baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
            if not good:
                report['fallback_binary_copy_used']=True;report['component_PFP_verified']=False;report['expected_outcome_verified']=False
                restore_owned(baseline_binary,baseline_bytes,baseline_mode,baseline_parent)
            report['baseline_binary_final_pristine']=baseline_binary.parent.resolve()==baseline_parent and baseline_binary.is_file() and not baseline_binary.is_symlink() and digest(baseline_binary.read_bytes())==baseline_hash and stat.S_IMODE(baseline_binary.stat().st_mode)==baseline_mode
        if not report['source_final_pristine'] or report.get('baseline_binary_final_pristine') is False:
            report['component_PFP_verified']=False;report['expected_outcome_verified']=False
        allcases=[case for row in report.get('phases',{}).values() for case in row.get('cases',[])]
        report['runtime_attempted']=any(case.get('runtime_attempted') for case in allcases)
        report['actual_body_counts']=aggregate(allcases,3 if expected=='pfp' and mutation_attempted else 1)
        for key in ['passed','failed','ignored','executed_nonignored']:report['actual_'+key]=report['actual_body_counts']['actual_'+key]
        if not report['runtime_attempted']:report['actual_executed_nonignored']=0
        report['qualification_passed']=False;save(report)
        ensure(report['source_final_pristine'] and report.get('baseline_binary_final_pristine',True),'final-source-binary-mode')
        if sys.exc_info()[0] is None:
            ensure(report.get('expected_outcome_verified') is True and without_fallback(report),'final-outcome-without-fallback-required')
            if expected=='pfp':ensure(report['component_PFP_verified'],'final-PFP-must-remain-qualified')

def filesystem_and_sequence_controls():
    # Remote synthetic fixtures only: no Cargo, binary, SDK or protocol process.
    events=[]
    def attempt():events.append('mutant')
    def restore():events.append('restore-exact-source')
    def fresh():events.append('fresh-compile-and-restored-body')
    try:admitted_mutation_sequence(False,attempt,restore,fresh)
    except ValueError:pass
    ensure(events==[],'unqualified-baseline-starts-neither-mutation-nor-restoration')
    def failed():events.append('mutant');raise ValueError('synthetic')
    try:admitted_mutation_sequence(True,failed,restore,fresh)
    except ValueError:pass
    ensure(events==['mutant','restore-exact-source','fresh-compile-and-restored-body'],'mutant-failure-still-fresh-restored-sequence')
    with tempfile.TemporaryDirectory(prefix='predecessor-controls-',dir=os.environ['RUNNER_TEMP']) as directory:
        root=Path(directory)/'checkout';outside=Path(directory)/'outside';root.mkdir();outside.mkdir()
        target=outside/'file';target.write_bytes(b'outside-unchanged')
        (root/'parent').symlink_to(outside,target_is_directory=True)
        ensure(not within(root/'parent'/'file',root),'regular-leaf-through-parent-symlink-escape-rejected')
        ensure(not within(outside,root) and within(root/'ordinary',root),'output-outside-and-contained-path-control')
        owned=root/'owned';data=b'exact-original';mode=0o640
        for condition in ['missing','symlink','wrong-mode']:
            if owned.is_symlink() or owned.exists():owned.unlink()
            if condition=='symlink':owned.symlink_to(target)
            if condition=='wrong-mode':owned.write_bytes(b'mutant');owned.chmod(0o755)
            restore_owned(owned,data,mode,root.resolve())
            ensure(owned.is_file() and not owned.is_symlink() and owned.read_bytes()==data and stat.S_IMODE(owned.stat().st_mode)==mode,'synthetic-owned-source-exact-restoration')
        ensure(target.read_bytes()==b'outside-unchanged','symlink-restore-never-writes-outside-target')
        original_parent=root/'replaced-parent';original_parent.mkdir();approved=original_parent.resolve();original_parent.rmdir()
        outside_owned=outside/'owned';outside_owned.write_bytes(b'outside-owned-unchanged');original_parent.symlink_to(outside,target_is_directory=True)
        for operation in [write_fresh,restore_owned]:
            try:operation(original_parent/'owned',data,mode,approved);accepted=True
            except ValueError:accepted=False
            ensure(not accepted and outside_owned.read_bytes()==b'outside-owned-unchanged','actual-owned-write-and-restore-reject-parent-escape-before-writing')
    for flag in ['fallback_source_restore_used','fallback_binary_copy_used']:
        ensure(not without_fallback({flag:True}),'any-fallback-disqualifies')
    ensure(without_fallback({}),'no-fallback-positive')
    return {'baseline_failure_no_mutation_or_restore':True,'mutant_failure_fresh_restore_required':True,'parent_symlink_escape_rejected':True,'actual_write_and_restore_parent_escape_rejected':True,
        'restore_conditions':['missing','symlink','wrong-mode'],'fallback_disqualifies':True,'actual_target_processes':0}

def controls():
    own,wrapper=expected_sites()
    record='native-predecessor-readiness exact=true live=true primary=false pending=true no_policy=true successor_policies=true shutdown_returns=3 storage_closed=true native_denial=false waiting_ok=true\n'
    prefix='running 1 test\ntest '+NAME+' ... '
    summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'
    green=prefix+record+'ok\n'+summary
    def check(raw,code,expected):return verdict(raw,code,counts.parse_body(raw,code,NAME),expected)['expected_outcome_verified']
    ensure(check(green,0,'green'),'readiness-GREEN-shaped-positive')
    def header(name,site,message,pid=''):
        return "thread '"+name+"'"+pid+' panicked at '+site[0]+':'+str(site[1])+':'+str(site[2])+':\n'+message+'\n'
    p=header('native-predecessor-readiness',own,MESSAGE)
    w=header(NAME,wrapper,'called `Result::unwrap()` on an `Err` value: Any { .. }')
    red=prefix+record.replace('native_denial=false waiting_ok=true','native_denial=true waiting_ok=false')+p+w+'FAILED\n'+summary.replace('result: ok. 1 passed; 0 failed','result: FAILED. 0 passed; 1 failed')
    ensure(check(red,101,'red'),'source-owned-two-panic-RED-positive')
    ensure(check(red.replace("' panicked at", "' (123) panicked at"),101,'red'),'discarded-numeric-PID-positive')
    negatives=[red.replace('native_denial=true','native_denial=false'),red.replace('waiting_ok=false','waiting_ok=true'),red.replace('primary=false','primary=true'),red.replace('shutdown_returns=3','shutdown_returns=2'),red.replace(MESSAGE,'private assertion'),red.replace(p,''),red.replace(w,''),red+p,red+w,red+record,red.replace('0 ignored','1 ignored'),red.replace('0 passed; 1 failed','0 passed; 0 failed'),red.replace(NAME,'foreign'),red.replace('shutdown_returns=3','shutdown_returns=18446744073709551616'),red+'error[E0000]: private\n',red.replace('exact=true','exact=1'),red.replace('exact=true','exact=PRIVATE')]
    negatives += [red.replace(k+'=true',k+'=false') for k in ['exact','live','pending','no_policy','successor_policies','storage_closed']]
    negatives += [red.replace(k+'=true ','') for k in ['exact','live','pending','no_policy','successor_policies','storage_closed']]
    for text in negatives:
        try:accepted=check(text,101,'red')
        except (ValueError,TypeError,OverflowError):accepted=False
        ensure(not accepted,'wrong-setup-error-panic-cleanup-or-width-never-intended-RED')
    ensure(not check(green.replace('waiting_ok=true','waiting_ok=false'),0,'green'),'waiting-Ok-required-GREEN')
    ensure(not check(green.replace('native_denial=false','native_denial=true'),0,'green'),'no-native-denial-GREEN')
    sample=b'predicate-and-observation\n'+GATE.encode()+b'policy-transaction\n';expected=sample.replace(GATE.encode(),b'',1)
    ensure(omitted_gate(sample,GATE,digest(expected))==expected,'gate-only-omission-data-control')
    bad_sources=[sample+GATE.encode(),expected,sample+b'unrelated']
    for candidate in bad_sources:
        try:omitted_gate(candidate,GATE,digest(expected));accepted=True
        except ValueError:accepted=False
        ensure(not accepted,'omission-anchor-count-and-unrelated-change-rejected')
    lifecycle=filesystem_and_sequence_controls()
    return {'filesystem_and_sequence_controls':lifecycle,'mutation_data_positive':1,'mutation_data_negative':3,'positive':3,'negative':len(negatives)+2,'body_count_controls':counts.parser_controls(),'runtime_bodies':0}

def main():
    global _FINAL_ADMISSION
    parser=argparse.ArgumentParser();parser.add_argument('--preflight',action='store_true');parser.add_argument('--expected',choices=['green','pfp'],default='pfp');parser.add_argument('--final-source');args=parser.parse_args()
    report={'scope':'one real exact-predecessor waiting contract; gate omission PFP','preflight':args.preflight,'expected':args.expected,'runtime_attempted':False,
        'actual_executed_nonignored':0,'qualification_passed':False,'native_global_qualification':False,'automatic_retries':0,'fixture_Tokio_workers':2,'composed_runtime_stack_bytes':8388608,'RUST_MIN_STACK':4194304,
        'original_outer_body_seconds':900,'raw_output_retained':False,'original_fixture_waits_unchanged':True}
    try:
        report['source_guard']=source_guard(args.preflight,args.final_source)
        if args.final_source is not None:_FINAL_ADMISSION=report['source_guard']
        save(report);report['parser_controls']=controls();report['final_admission_controls']=final_admission_controls();save(report)
        if not args.preflight:runtime(report,'experimental',args.expected)
        report['controller_completed']=True;save(report)
    except Exception as error:report['controller_failure_type']=type(error).__name__;save(report);raise
    finally:
        if args.final_source is not None:
            def final_probe():
                admitted=source_guard(args.preflight,args.final_source)['whole_source_modes_verified']
                report['final_git_closure']=git_closure()
                report['final_HEAD_git_pristine']=report['final_git_closure']['tracked_HEAD_pristine']
                return admitted and report['final_git_closure']['verified']
            if not final_admission_close(report,final_probe):
                report['final_git_closure']={'verified':False,'tracked_HEAD_pristine':False}
                report['final_HEAD_git_pristine']=False
        else:
            report['final_git_closure']=git_closure();report['final_HEAD_git_pristine']=report['final_git_closure']['tracked_HEAD_pristine']
        if not report['final_git_closure']['verified']:report['component_PFP_verified']=False;report['expected_outcome_verified']=False
        save(report)
        if args.final_source is not None:ensure(report.get('final_source_admission_exact') is True,'final-source-admission-closure')
        ensure(report['final_git_closure']['verified'],'final-tracked-index-untracked-Git-closure')
if __name__=='__main__':main()
