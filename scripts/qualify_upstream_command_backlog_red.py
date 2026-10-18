#!/usr/bin/env python3
"""One real SDK bounded-command arbitration RED. No native/product qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import qualify_upstream_storage_boundary as bounded
from upstream_completion_ci import compile_cases, digest, ensure, environment, identity, parse_body
from qualify_upstream_body_negative import freeze, layout, feature_identity

BASE = 'c3939a775d81f6d9380a9318ca9f729a774ef990'
SELF = 'scripts/qualify_upstream_command_backlog_red.py'
MANIFEST = 'scripts/command_backlog_source_manifest.json'
MANIFEST_SHA = 'e493e23876bbd04d6765b334600d4014b91c1ba453ad323e81c1735451980850'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-private-command-backlog-red-20261018'
BEGIN = '  # COMMAND_BACKLOG_RED_JOBS_BEGIN\n'
END = '  # COMMAND_BACKLOG_RED_JOBS_END\n'
OPTIONS = 'options: [command-backlog-preflight, command-backlog-red, '
OUT = Path('command-backlog-red-evidence')
CASE = 'authenticated_body_is_serviced_before_eight_queued_history_reads'
NAME = 'native_device_linking::automatic_pairing_acceptance::command_backlog_acceptance::' + CASE
FIXTURE = 'crates/marmot-app/src/native_device_linking/tests/command_backlog_acceptance.rs'
MESSAGE = 'authenticated_body_must_precede_second_queued_history_read'
FIELDS = ['real_consent_held','request_ack_harvested','exact_peer_proof_held','paused_live_prerequisites',
          'actual_first_message_id','queue_head_witness','eight_commands_installed','authenticated_exact_body',
          'eight_replies_ok','normal_enrollment','public_cancelled','bounded_command_order','probe_known']


def source_guard():
    head = subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_REPOSITORY') == 'dyKiU/mdk'
           and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_SHA') == head
           and os.environ.get('GITHUB_REF') == REF
           and os.environ.get('GITHUB_WORKFLOW_REF') == 'dyKiU/mdk/' + WORKFLOW + '@' + REF
           and os.environ.get('COMMAND_BACKLOG_BASELINE') == BASE, 'owned-exact-remote-cohort')
    ensure(os.environ.get('CARGO_BUILD_JOBS') == '2' and os.environ.get('CARGO_INCREMENTAL') == '1'
           and os.environ.get('RUST_MIN_STACK') == '4194304'
           and all(os.environ.get(k) == '0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
           and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP',
                   'CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']), 'unchanged-capacity')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode == 0, 'initial-pristine')
    ensure(digest(Path(MANIFEST).read_bytes()) == MANIFEST_SHA, 'reviewed-manifest')
    manifest = json.loads(Path(MANIFEST).read_text())
    ensure(manifest['baseline'] == BASE and manifest['baseline_is_diagnostic_overlay'] is True, 'honest-overlay-baseline')
    baseline = {}
    for item in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if item:
            meta,name = item.split(b'\t',1); file_mode,kind,blob = meta.decode().split()
            ensure(kind == 'blob' and file_mode in {'100644','100755','120000'}, 'ordinary-baseline')
            baseline[os.fsdecode(name)] = (file_mode,blob)
    added = {SELF,MANIFEST} | set(manifest['new_files'])
    current = layout()
    ensure(not added.intersection(baseline) and set(current) == set(baseline) | added, 'whole-inventory')
    for name,meta in current.items():
        file_mode,blob = baseline.get(name,('100644',None))
        ensure(meta['git_mode'] == file_mode and meta['symlink'] == (file_mode == '120000')
               and (meta['symlink'] or meta['actual_executable'] == (file_mode == '100755')), 'whole-modes')
        data = os.fsencode(os.readlink(name)) if meta['symlink'] else Path(name).read_bytes()
        if name in manifest['changes']:
            change = manifest['changes'][name]
            ensure(digest(data) == change['after_sha256'] and file_mode == change['git_mode'], 'full-hook-pin')
            text = data.decode()
            for edit in reversed(change['edits']):
                ensure(text.count(edit['after']) == 1, 'unique-reverse-context')
                text = text.replace(edit['after'],edit['before'],1)
            data = text.encode(); ensure(digest(data) == change['before_sha256'], 'exact-hook-reversal')
        if name in manifest['new_files']:
            ensure(digest(data) == manifest['new_files'][name]['sha256'], 'exact-new-test-source')
        if name == WORKFLOW:
            text = data.decode(); ensure(text.count(BEGIN) == text.count(END) == text.count(OPTIONS) == 1, 'isolated-workflow')
            before,rest = text.split(BEGIN); _,after = rest.split(END)
            data = (before + after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None:
            ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() == blob, 'entire-baseline-reconstructed:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()) <= {str(OUT/'result.json')}, 'no-other-overlay')
    return {'source':head,'baseline':BASE,'baseline_is_diagnostic_overlay':True,'whole_source_modes_reconstructed':True,
            'pure_product_qualification':False,'historical_runtime_evidence_reused':False}


def assertion_line():
    lines = Path(FIXTURE).read_text().splitlines(); sites = [i for i,line in enumerate(lines) if MESSAGE in line]
    ensure(len(sites) == 1,'unique-final-oracle')
    return max(i for i in range(sites[0]+1) if re.search(r'\bassert!\s*\(',lines[i])) + 1


def parse(raw,code):
    ensure(len(raw.encode()) <= 8*1024*1024,'bounded-runtime')
    clean = re.sub(r'\x1b\[[0-9;]*m','',raw)
    names = re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.',clean)
    clean = re.sub(r'(?m)^test '+re.escape(NAME)+r' \.\.\. (?=command-backlog )','',clean)
    row = dict(parse_body(clean,CASE),body_exit_code=code,executed_case_names=names,
               compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',clean,re.M)),
               running_counts=[int(v) for v in re.findall(r'(?m)^running ([0-9]{1,3}) tests?$',clean)])
    markers = [line for line in clean.splitlines() if line.startswith('command-backlog')]
    row['marker_header_count'] = len(markers)
    pattern = (r'command-backlog facts=\['+', '.join([r'(true|false)']*13)+r'\] completed_before=(None|Some\([0-8]\))'
               +r' runtime_closes=([0-3]) plane_shutdown_returns=([0-3]) relay_closed=(true|false) attempt_completed=(true|false)')
    ensure(len(markers) == 1 and len(markers[0]) < 1024,'sole-closed-marker')
    found = re.fullmatch(pattern,markers[0]); ensure(found is not None,'typed-marker')
    values = found.groups(); row['facts'] = dict(zip(FIELDS,[v == 'true' for v in values[:13]]))
    row.update(completed_before=None if values[13] == 'None' else int(values[13][5:-1]),runtime_closes=int(values[14]),
               plane_shutdown_returns=int(values[15]),relay_closed=values[16]=='true',attempt_completed=values[17]=='true',
               named_final_assertion_observed=MESSAGE in clean)
    return row


def intended_red(row):
    locations = row.get('panic_locations',[])
    return (all(type(row.get(k)) is int and row[k] == v for k,v in {'body_exit_code':101,'passed':0,'failed':1,
             'ignored':0,'executed_nonignored':1,'compiler_error_count':0,'all_panic_header_count':1,'marker_header_count':1}.items())
        and row.get('running_counts') == [1] and row.get('executed_case_names') == [NAME]
        and row.get('named_final_assertion_observed') is True
        and all(row.get('facts',{}).get(k) is True for k in FIELDS if k != 'bounded_command_order')
        and row.get('facts',{}).get('bounded_command_order') is False
        and type(row.get('completed_before')) is int and 2 <= row['completed_before'] <= 8
        and type(row.get('runtime_closes')) is int and row['runtime_closes'] == 3
        and type(row.get('plane_shutdown_returns')) is int and row['plane_shutdown_returns'] == 3
        and row.get('relay_closed') is True and row.get('attempt_completed') is True
        and len(locations) == 1 and locations[0]['file'] == FIXTURE and locations[0]['line'] == assertion_line()
        and not row.get('watchdog_triggered') and not row.get('actual_count_unknown'))


def parser_controls():
    bits = ['true']*13; bits[11] = 'false'
    marker = 'command-backlog facts=['+', '.join(bits)+'] completed_before=Some(8) runtime_closes=3 plane_shutdown_returns=3 relay_closed=true attempt_completed=true'
    raw = 'running 1 test\ntest '+NAME+' ... FAILED\n'+marker+'\nthread test panicked at '+FIXTURE+':'+str(assertion_line())+':5:\n'+MESSAGE+'\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
    row = parse(raw,101); ensure(intended_red(row),'sole-runtime-order-RED-positive')
    ensure(intended_red(parse(raw.replace(' ... FAILED\n'+marker,' ... '+marker),101)),'shared-prefix-positive')
    negatives = 0
    for delta in [{'passed':True},{'failed':True},{'ignored':False},{'body_exit_code':True},{'completed_before':True},
                  {'completed_before':None},{'completed_before':1},{'completed_before':9},{'passed':1},{'failed':0},
                  {'ignored':1},{'executed_nonignored':0},{'compiler_error_count':1},{'all_panic_header_count':2},
                  {'running_counts':[0]},{'executed_case_names':[NAME,NAME]},{'runtime_closes':2},
                  {'plane_shutdown_returns':2},{'relay_closed':False},{'attempt_completed':False},
                  {'named_final_assertion_observed':False},{'watchdog_triggered':True},{'actual_count_unknown':True},
                  {'panic_locations':[]},{'panic_locations':[{'file':FIXTURE,'line':assertion_line()+1,'column':5}]}]:
        ensure(not intended_red(dict(row,**delta)),'non-RED-rejected'); negatives += 1
    for field in FIELDS:
        ensure(not intended_red(dict(row,facts=dict(row['facts'],**{field:not row['facts'][field]}))),'all-prerequisites-required'); negatives += 1
    for bad in [raw+'\n'+marker,raw.replace('Some(8)','Some(99)'),raw.replace(marker,marker+' raw=private')]:
        try: parse(bad,101)
        except ValueError: negatives += 1; continue
        raise ValueError('unclosed-marker-accepted')
    ensure(not intended_red(parse(raw.replace(NAME,NAME+'_other'),101)),'wrong-name-rejected'); negatives += 1
    return {'positive':2,'negative':negatives,'runtime_bodies':0}


def main(options):
    os.umask(0o077); OUT.mkdir(exist_ok=True)
    report = {'behavioral_red_verified':False,'qualification_passed':False,'green_claim':False,'mutation_claim':False,
              'positive_native_acceptance_claim':False,'actual_counts_complete':False,'actual_runtime':None,'runtime_started':False}
    before = modes = None
    def save(): (OUT/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    try:
        report['source_guard']=source_guard(); report['parser_controls']=parser_controls(); save()
        if options.preflight: report['preflight_passed']=True; save(); return
        report['environment']=environment(); before,modes=freeze(),layout()
        report['input_manifest_sha256']=identity(before)
        compilation,cases=compile_cases([CASE])
        headers=compilation.pop('compiler_headers',[])
        compilation['compiler_codes']=sorted(set(re.findall(r'error\[(E[0-9]{4})\]', '\n'.join(headers))))
        compilation['compiler_sites']=[{'file':p,'line':int(n),'column':int(c)} for p,n,c in re.findall(r'--> (crates/[A-Za-z0-9_./-]+\.rs):([0-9]+):([0-9]+)','\n'.join(headers))]
        report['compilation']=compilation; save()
        ensure(compilation.get('compile_exit_code') == compilation.get('compiler_error_count') == 0
               and compilation.get('compiled_fingerprints',{}).get('verified') is True
               and set(cases)=={CASE} and cases[CASE]['name']==NAME,'one-real-feature-verified-case')
        report['feature_identity']=feature_identity(compilation); case=cases[CASE]
        ensure(freeze()==before and layout()==modes and digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'before-body-pristine')
        report['runtime_started']=True; report['binary_sha256']=case['binary_sha256']; save()
        code,raw,seconds=bounded.capture([case['binary'],'--exact',NAME,'--nocapture','--test-threads=1'],300,limit=8*1024*1024)
        report['actual_runtime']=dict(parse_body(raw,CASE),body_exit_code=code,seconds=seconds,
            compiler_error_count=len(re.findall(r'^error(?:\[E[0-9]+\])?:',raw,re.M)))
        save()
        row=parse(raw,code); report['actual_runtime']=dict(row,seconds=seconds); save()
        report['actual_counts_complete']=all(type(row.get(k)) is int for k in ['passed','failed','ignored','executed_nonignored']) and row['passed']+row['failed']==row['executed_nonignored']==1 and row['ignored']==0
        ensure(report['actual_counts_complete'] and intended_red(row),'sole-authenticated-order-runtime-RED-required')
        ensure(digest(Path(case['binary']).read_bytes())==case['binary_sha256'],'binary-pristine')
        report['behavioral_red_verified']=True
    except bounded.GateFailure as error:
        report['watchdog_triggered']=str(error)=='bounded-command-timeout'
        report['output_limit_triggered']=str(error)=='bounded-command-output-limit'
        report['actual_count_unknown']=True; report['exception_type']=type(error).__name__; raise
    except Exception as error:
        report['exception_type']=type(error).__name__; raise
    finally:
        if before is not None:
            report['inputs_pristine']=freeze()==before and layout()==modes
            if not report['inputs_pristine']: report['behavioral_red_verified']=False
        save()
        if before is not None: ensure(report['inputs_pristine'],'final-pristine')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--preflight',action='store_true'); main(parser.parse_args())
