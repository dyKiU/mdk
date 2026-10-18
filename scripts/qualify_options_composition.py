#!/usr/bin/env python3
"""One real Rust options test; exact source restoration; no protocol qualification."""
import argparse,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path
import qualify_upstream_storage_boundary as bounded # capture only; never its guard/main/parser
BASE='580c1730836e4236d552bd85b6a25cdfce5c9e31'
REF='refs/heads/ci/upstream-integration-refresh-20261018'
SELF='scripts/qualify_options_composition.py'
WORKFLOW='.github/workflows/options-composition-pfp.yml'
WORKFLOW_SHA256='31acad353d9b4c1a2eb16c32ad6cc5ebf39ce5cf85720bd9e935d2483cd22734'
PRODUCT='crates/marmot-uniffi/src/lib.rs'
NAME='tests::runtime_options_compose_deployment_and_dedicated_pairing_routes'
PAYLOAD='combined_deployment_must_preserve_explicit_pairing_routes'
BEFORE='            .with_moderation_report_config(self.moderation_report_config.clone().map(Into::into))\n            .with_pairing_relay_urls(self.pairing_relay_urls.clone().unwrap_or_default());'
AFTER='            .with_moderation_report_config(self.moderation_report_config.clone().map(Into::into));'
OUT=Path('options-composition-evidence')
PEER_METADATA={'scripts/qualify_upstream_pure_command_offer.py','scripts/qualify_upstream_pure_native5.py','scripts/pure_command_offer_source_manifest.json'}
PEER_WORKFLOW='.github/workflows/experimental-sync-ci.yml'
ensure=bounded.ensure
def sha(data):return hashlib.sha256(data).hexdigest()
def git(*args):return subprocess.check_output(['git',*args]).decode().strip()
def freeze():
    result={}
    for path in subprocess.check_output(['git','ls-files','-z']).decode().split('\0'):
        if not path:continue
        p=Path(path);mode=p.lstat().st_mode
        result[path]=[stat.S_IMODE(mode),'link' if p.is_symlink() else 'file',sha(os.fsencode(os.readlink(p)) if p.is_symlink() else p.read_bytes())]
    return result


OVERLAYS=[
    {'name':'offer','begin':'  # PURE_COMMAND_OFFER_JOBS_BEGIN\n','end':'  # PURE_COMMAND_OFFER_JOBS_END\n',
     'options':'options: [pure-command-offer-preflight, pure-command-offer-pfp, '},
    {'name':'native5','begin':'  # PURE_NATIVE5_JOBS_BEGIN\n','end':'  # PURE_NATIVE5_JOBS_END\n',
     'options':'options: [pure-native5-preflight, pure-native5-green, '},
]


def strip_owned_workflow(data, required):
    text=data.decode()
    present=[(text.count(item['begin']),text.count(item['end'])) for item in OVERLAYS]
    if not required and all(row==(0,0) for row in present):
        ensure(all(item['options'] not in text for item in OVERLAYS),'no-unowned-option-prefix-without-blocks')
        return data
    ensure(all(row==(1,1) for row in present),'exact-complete-owned-workflow-union')
    for overlay in OVERLAYS:
        before,rest=text.split(overlay['begin']);_,after=rest.split(overlay['end']);text=before+after
    for overlay in OVERLAYS:
        ensure(text.count(overlay['options'])==1,'exact-owned-option-prefix-order')
        text=text.replace(overlay['options'],'options: [',1)
    return text.encode()


def workflow_metadata_controls():
    # Synthetic metadata only: no source reads, builds, protocol bodies or RED claim.
    bare='name: synthetic\noptions: [legacy]\njobs:\n'
    full=bare
    for overlay in reversed(OVERLAYS):full=full.replace('options: [',overlay['options'],1)
    blocks=[item['begin']+'  owned_'+item['name']+': synthetic\n'+item['end'] for item in OVERLAYS]
    full+=''.join(blocks)
    ensure(strip_owned_workflow(bare.encode(),False)==bare.encode(),'workflow-optional-absent-positive')
    ensure(strip_owned_workflow(full.encode(),True)==bare.encode(),'workflow-current-complete-positive')
    ensure(strip_owned_workflow(full.encode(),False)==bare.encode(),'workflow-BASE-complete-positive')
    bad=[(bare,True),
        (full.replace(blocks[0],'',1),False),
        (full+blocks[0],True),
        (full.replace(OVERLAYS[1]['end'],'',1),True),
        (full.replace(OVERLAYS[0]['options']+'pure-native5-preflight, pure-native5-green, ',
            OVERLAYS[1]['options']+'pure-command-offer-preflight, pure-command-offer-pfp, ',1),True),
        (full.replace(''.join(blocks),'',1),False),
        (full.replace(OVERLAYS[0]['options'],'options: [',1),True),
        (full.replace(OVERLAYS[0]['options'],OVERLAYS[0]['options']+'pure-command-offer-preflight, pure-command-offer-pfp, ',1),True)]
    for candidate,required in bad:
        rejected=False
        try:strip_owned_workflow(candidate.encode(),required)
        except ValueError:rejected=True
        ensure(rejected,'malformed-owned-workflow-union-rejected')
    changed_owned=full.replace('owned_offer: synthetic','owned_offer: reviewed-change',1)
    ensure(strip_owned_workflow(changed_owned.encode(),True)==bare.encode(),'only-declared-owned-body-removed')
    foreign=full.replace('name: synthetic','name: foreign',1)
    expected_foreign=bare.replace('name: synthetic','name: foreign',1).encode()
    normalized=strip_owned_workflow(foreign.encode(),True)
    ensure(normalized==expected_foreign and normalized!=strip_owned_workflow(bare.encode(),False),'foreign-outside-bytes-survive-and-mismatch')
    return {'synthetic_metadata_positive':3,'malformed_union_negative':len(bad),
        'owned_body_normalized':1,'foreign_outside_comparison_mismatch':1,'actual_runtime_bodies':0}

def source_guard():
    head=git('rev-parse','HEAD')
    ensure(type(BASE) is str and re.fullmatch('[0-9a-f]{40}',BASE),'signed-formatted-BASE-unpinned')
    ensure(type(WORKFLOW_SHA256) is str and re.fullmatch('[0-9a-f]{64}',WORKFLOW_SHA256),'workflow-unpinned')
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk' and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF and os.environ.get('OPTIONS_COMPOSITION_BASELINE')==BASE,'exact-manual-head')
    ensure(git('diff','--name-only','HEAD')=='','whole-HEAD-pristine')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    old={}
    for entry in subprocess.check_output(['git','ls-tree','-rz',BASE]).split(b'\0'):
        if entry:
            meta,path=entry.split(b'\t');mode,kind,blob=meta.decode().split();ensure(kind=='blob','blob-only-source');old[os.fsdecode(path)]=(mode,blob)
    ensure(PEER_METADATA<=set(old) and all(old[p][0]=='100644' for p in PEER_METADATA),'exact-peer-metadata-existing-in-BASE')
    current=freeze();ensure(SELF not in old and WORKFLOW not in old and set(current)==set(old)|{SELF,WORKFLOW},'whole-BASE-plus-only-two-metadata')
    for path,(mode,blob) in old.items():
        p=Path(path);data=os.fsencode(os.readlink(p)) if p.is_symlink() else p.read_bytes()
        ensure((p.is_symlink() and mode=='120000') or (not p.is_symlink() and mode in {'100644','100755'} and bool(p.stat().st_mode&0o111)==(mode=='100755')),'whole-BASE-mode')
        if path in PEER_METADATA:
            ensure(not p.is_symlink() and current[path][0]==0o644,'peer-metadata-mode')
            continue # Exactly these three metadata files: actual GitHEAD==GITHUB_SHA/pristine-bound.
        if path==PEER_WORKFLOW:
            expected=subprocess.check_output(['git','cat-file','blob',blob])
            ensure(strip_owned_workflow(data,True)==strip_owned_workflow(expected,False),'peer-workflow-outside-two-owned-blocks-exact')
            continue
        ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'whole-BASE-content')
    for p in [SELF,WORKFLOW]:ensure(not Path(p).is_symlink() and current[p][0]==0o644,'metadata-mode')
    ensure(sha(Path(WORKFLOW).read_bytes())==WORKFLOW_SHA256,'workflow-exact')
    ensure(set(git('ls-files','--others','--exclude-standard').splitlines())<={str(OUT/'result.json')},'no-untracked-source')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2' and os.environ.get('RUST_MIN_STACK')=='4194304' and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG']) and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP']),'bounded-build-profile')
    return {'source':head,'baseline':BASE,'full_content_modes':True,'Rust_exceptions':[],
        'peer_metadata_commit_bound_only':sorted(PEER_METADATA),'peer_workflow_only_two_blocks_normalized':True,
        'all_other_metadata_and_workflow_bytes_BASE_exact':True,'peer_guards_main_globals_called_or_mutated':False}

def parse(raw,code,line):
    raw=re.sub(r'\x1b\[[0-9;]*m','',raw)
    summaries=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',raw,re.M)
    names=re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. ',raw,re.M)
    headers=re.findall(r"^thread '([^'\n]+)'(?: \(([1-9][0-9]{0,19})\))? panicked at ([^\n]+):\n",raw,re.M)
    row={'exit_code':code,'passed':None,'failed':None,'ignored':None,'executed_nonignored':None,'actual_counts_complete':False,'exact_name':names==[NAME],'panic_count':raw.count('panicked at '),'compiler_error_count':len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)),'intended_panic':False}
    if len(summaries)==1:
        status,p,f,i,m,_=summaries[0];p,f,i=int(p),int(f),int(i)
        row.update(passed=p,failed=f,ignored=i,executed_nonignored=p+f,actual_counts_complete=(p+f==1 and i==0 and int(m)==0 and names==[NAME] and status==('FAILED' if f else 'ok')))
    row['intended_panic']=(len(headers)==1 and headers[0][0]==NAME and (not headers[0][1] or int(headers[0][1])<=18446744073709551615) and headers[0][2]==PRODUCT+':'+str(line)+':9' and len(re.findall('^'+re.escape(PAYLOAD)+'$',raw,re.M))==1 and row['panic_count']==1)
    return row

def green(row):return row['actual_counts_complete'] and row['exit_code']==0 and row['passed']==1 and row['failed']==0 and row['ignored']==0 and row['panic_count']==0 and row['compiler_error_count']==0
def killed(row):return row['actual_counts_complete'] and row['exit_code']==101 and row['passed']==0 and row['failed']==1 and row['ignored']==0 and row['compiler_error_count']==0 and row['intended_panic']
def controls():
    summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out;\n'
    good='test '+NAME+' ... ok\n'+summary
    bad='test '+NAME+' ... \nthread \''+NAME+"' panicked at "+PRODUCT+':9:9:\n'+PAYLOAD+'\nFAILED\n'+summary.replace('ok. 1 passed; 0 failed','FAILED. 0 passed; 1 failed')
    ensure(green(parse(good,0,9)) and killed(parse(bad,101,9)) and killed(parse(bad.replace("' panicked", "' (123) panicked"),101,9)),'closed-parser-positive')
    adversaries=[bad.replace(NAME,'tests::foreign'),bad.replace(':9:9:',':10:9:'),bad.replace(PAYLOAD,'foreign_payload'),bad+bad,bad.replace('0 ignored','1 ignored'),bad.replace('1 failed','0 failed'),bad+'error[E0001]: private\n',bad.replace("' panicked", "' (0) panicked"),bad.replace(PAYLOAD,PAYLOAD+' PRIVATE'),bad.replace("' panicked", "' (18446744073709551616) panicked")]
    for raw in adversaries:ensure(not killed(parse(raw,101,9)),'closed-parser-negative')
    return {'positive':3,'negative':len(adversaries),'runtime_bodies':0,'raw_output_exported':False,'peer_workflow_union':workflow_metadata_controls()}

def write_owned(data,mode):
    p=Path(PRODUCT);previous=p.stat().st_mtime_ns if p.exists() else 0
    if p.is_symlink():p.unlink()
    p.write_bytes(data);p.chmod(mode);fresh=max(time.time_ns(),previous+1);os.utime(p,ns=(fresh,fresh))

def main(cohort):
    os.umask(0o077);OUT.mkdir(exist_ok=True);report={'scope':'one Rust options-conversion test PFP','cohort':cohort,'qualified':False,'protocol_native_qualification':False,'automatic_retries':0,'phases':{}}
    def save():(OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    initial=None;original=None;mode=None;binary=None;backup=None;binary_mode=None;baseline_binary=None
    try:
        report['source_guard']=source_guard();report['parser_controls']=controls();save()
        initial=freeze();original=Path(PRODUCT).read_bytes();mode=Path(PRODUCT).stat().st_mode&0o777
        text=original.decode();ensure(text.count(BEFORE)==1 and text.count('fn '+NAME.split('::')[-1]+'()')==1,'sole-owned-anchors')
        mutated=text.replace(BEFORE,AFTER,1).encode();lines=mutated.decode().splitlines();site=next(i for i,value in enumerate(lines,1) if 'config.pairing_relay_urls == pairing' in value)-1
        report['oracle']={'name':NAME,'path':PRODUCT,'mutant_line':site,'column':9,'payload':PAYLOAD};save()
        def phase(label,expected):
            nonlocal binary,backup,binary_mode,baseline_binary
            row={};report['phases'][label]=row;save()
            command=['cargo','test','--locked','-p','marmot-uniffi','--lib','--no-run','--message-format=json']
            if cohort=='experimental':command+=['--features','experimental-device-sync']
            code,raw,seconds=bounded.capture(command,1200,limit=16*1024*1024)
            clean=re.sub(r'\x1b\[[0-9;]*m','',raw);events=[]
            for value in clean.splitlines():
                if value.startswith('{'):
                    try:events.append(json.loads(value))
                    except json.JSONDecodeError:pass
            errors=[e for e in events if e.get('reason')=='compiler-message' and e.get('message',{}).get('level')=='error']
            artifacts=[e for e in events if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='marmot_uniffi' and e.get('profile',{}).get('test') is True and e.get('executable')]
            row['compile']={'command':command,'exit_code':code,'seconds':seconds,'compiler_error_count':len(errors),'closed_error_codes':sorted({e['message']['code']['code'] for e in errors if e['message'].get('code') and re.fullmatch('E[0-9]{4}',e['message']['code']['code'])})[:32]};save()
            ensure(code==0 and not errors and len(artifacts)==1,'compile-real-test-required')
            artifact=artifacts[0];features=sorted(artifact['features']);row['features']=features
            ensure(('experimental-device-sync' in features)==(cohort=='experimental') and set(features)<={'default','experimental-device-sync'},'exact-cohort')
            binary=Path(artifact['executable']);ensure(binary.is_file() and not binary.is_symlink(),'actual-binary')
            identity=[sha(binary.read_bytes()),binary.stat().st_mode&0o777];row['binary_before']=identity
            if label=='baseline':
                ensure(binary.stat().st_size<=512*1024*1024,'bounded-binary-backup');backup=binary.read_bytes();binary_mode=identity[1];baseline_binary=identity[0]
            else:ensure(features==report['phases']['baseline']['features'],'same-features')
            for ignored in [False,True]:
                cmd=[str(binary),'--list','--format','terse','--exact',NAME]+(['--ignored'] if ignored else [])
                c,inventory,_=bounded.capture(cmd,30,limit=65536);entries=inventory.splitlines()
                summary=('0 tests, 0 benchmarks' if ignored else '1 test, 0 benchmarks')
                if entries and entries[-1]==summary:entries=entries[:-1]
                ensure(c==0 and entries==([] if ignored else [NAME+': test']),'exact-one-normal-zero-ignored-inventory')
            ensure(freeze()==expected,'before-body-source-pristine')
            c,raw,seconds=bounded.capture([str(binary),'--exact',NAME,'--nocapture','--test-threads=1'],60,limit=1024*1024)
            row['body_exit_code']=c;row['body_seconds']=seconds;row['source_after_body_pristine']=freeze()==expected;row['binary_after']=[sha(binary.read_bytes()),binary.stat().st_mode&0o777];save()
            row['body']=parse(raw,c,site);save()
            ensure(row['source_after_body_pristine'] and row['binary_after']==identity,'body-source-binary-pristine')
            ensure(killed(row['body']) if label=='mutant' else green(row['body']),'exact-runtime-oracle')
            if label=='restored':ensure(identity==[baseline_binary,binary_mode],'restored-original-binary')
        phase('baseline',initial)
        try:
            write_owned(mutated,mode);expected=freeze();ensure(set(expected)==set(initial) and all(expected[p]==initial[p] for p in initial if p!=PRODUCT) and expected[PRODUCT]==[mode,'file',sha(mutated)],'mutant-only-exact-product')
            phase('mutant',expected)
        finally:
            write_owned(original,mode);ensure(freeze()==initial,'restore-exact-source-before-recompile')
            phase('restored',initial)
        report['qualified']=True;report['aggregate']={key:sum(row['body'][field] for row in report['phases'].values()) for key,field in [('executed','executed_nonignored'),('passed','passed'),('intended_failed','failed'),('ignored','ignored')]};save()
    except Exception as error:
        report['exception_type']=type(error).__name__;report['qualified']=False
        if isinstance(error,bounded.GateFailure) and re.fullmatch('[a-z0-9-]{1,100}',str(error)):report['failure_gate']=str(error)
        save();raise
    finally:
        if original is not None:
            write_owned(original,mode);report['source_final_pristine']=freeze()==initial
        if binary is not None and backup is not None:
            if not binary.exists() or binary.is_symlink() or not binary.is_file() or sha(binary.read_bytes())!=baseline_binary or binary.stat().st_mode&0o777!=binary_mode:
                if binary.is_symlink():binary.unlink()
                binary.write_bytes(backup);binary.chmod(binary_mode);report['binary_fallback_used']=True;report['qualified']=False
            report['binary_final_pristine']=binary.is_file() and not binary.is_symlink() and sha(binary.read_bytes())==baseline_binary and binary.stat().st_mode&0o777==binary_mode
        if report.get('source_final_pristine') is False or report.get('binary_final_pristine') is False:report['qualified']=False
        save()
        if sys.exc_info()[0] is None:ensure(report['qualified'],'final-exact-closure-required')
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--cohort',choices=['default','experimental'],required=True);main(parser.parse_args().cohort)
