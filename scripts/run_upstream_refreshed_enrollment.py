"""One refreshed-source five-case cohort; not final SDK/native qualification."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time
import qualify_upstream_automatic_body as body
import upstream_completion_ci as ci
from verify_upstream_refreshed_enrollment_source import source_guard

OUT = Path('refreshed-enrollment-evidence')
SUFFIXES = [body.CASE, ci.NEW, *ci.ORIGINALS]
POLICY = 'runtime_suites_choose_their_tokio_flavor'
POLICY_NAME = 'runtime::tests::' + POLICY
NAMES = ['native_device_linking::automatic_pairing_acceptance::' + suffix for suffix in SUFFIXES]

def passed(row):
    if row.get('suffix') not in SUFFIXES: return False
    expected = NAMES[SUFFIXES.index(row['suffix'])]
    return row.get('test') == expected and row.get('named_cases') == [expected] and row.get('compiler_error_count') == 0 and not row.get('actual_count_unknown') and (body.body_green(row) if row['suffix'] == body.CASE else ci.green(row))

def policy_passed(row):
    return row.get('test')==POLICY_NAME and row.get('named_cases')==[POLICY_NAME] and row.get('body_exit_code')==0 and row.get('passed')==1 and row.get('failed')==0 and row.get('ignored')==0 and row.get('executed_nonignored')==1 and row.get('compiler_error_count')==0 and row.get('all_panic_header_count')==0 and not row.get('watchdog_triggered') and not row.get('actual_count_unknown')

def parser_preflight():
    report = {'body_parser': body.parser_preflight(), 'completion_parser': ci.parser_preflight()}
    positives = negatives = 0
    for suffix, name in zip(SUFFIXES, NAMES):
        row = {'suffix': suffix, 'test': name, 'named_cases': [name], 'body_exit_code': 0, 'passed': 1, 'failed': 0, 'ignored': 0, 'executed_nonignored': 1, 'compiler_error_count': 0, 'all_panic_header_count': 0, 'original_phase_markers': ['third-device-completion', 'third-device-completed', 'fourth-device-completion', 'fourth-device-completed']}
        if suffix == body.CASE: row.update(all_prerequisites_and_two_positive_closes=True, responsive_while_held=True)
        elif suffix == ci.NEW:
            stages = list(ci.STAGES); stages.insert(stages.index('periodic-arm-released'), 'fresh-actor-progress')
            row.update(stages=stages, observations={key: True for key in ['held_consent_task_success', 'public_snapshot_responsiveness', 'durable_policy_and_proof_with_gate', 'durable_policy_seen', 'proof_success_seen']}, original_phase_markers=['fourth-device-completion', 'fourth-device-completed'])
        else: row['hold_markers'] = ['sibling-consent-held-before-peer-progress', 'automatic-publication-held-before-completion']
        ci.ensure(passed(row), 'exact-case-green-positive'); positives += 1
        for change in [{'test': NAMES[(SUFFIXES.index(suffix)+1)%5]}, {'named_cases': [name, name]}, {'compiler_error_count': 1}, {'ignored': 1}, {'executed_nonignored': 0}, {'actual_count_unknown': True}, {'watchdog_triggered': True}, {'body_exit_code': 101}]:
            ci.ensure(not passed(dict(row, **change)), 'invalid-case-negative'); negatives += 1
    policy={'test':POLICY_NAME,'named_cases':[POLICY_NAME],'body_exit_code':0,'passed':1,'failed':0,'ignored':0,'executed_nonignored':1,'compiler_error_count':0,'all_panic_header_count':0}
    ci.ensure(policy_passed(policy),'upstream-policy-positive')
    for change in [{'test':NAMES[0]},{'named_cases':[]},{'body_exit_code':101},{'ignored':1},{'compiler_error_count':1},{'watchdog_triggered':True},{'actual_count_unknown':True}]:
        ci.ensure(not policy_passed(dict(policy,**change)),'upstream-policy-negative')
    report.update(source_policy_positive=1, source_policy_negative=7)
    report.update(exact_case_positive=positives, exact_case_negative=negatives, actual_product_bodies=0)
    return report

def preflight():
    report = source_guard()
    report['parser_preflight'] = parser_preflight()
    OUT.mkdir(exist_ok=True); (OUT/'preflight.json').write_text(json.dumps(report, indent=2)+'\n')
    return report

def run(mode, cohort):
    OUT.mkdir(exist_ok=True)
    report = ci.environment()
    report.update(mode=mode, runtime_cohort='experimental' if mode=='controls' else cohort, scope='exact refreshed upstream five unchanged controls plus affected statics; no final full/native/SDK qualification', qualification_passed=False, all_five_controls_passed=False, actual_runtime_bodies=0)
    def save(): (OUT/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    frozen = ci.freeze(); report['source_before_sha256'] = ci.identity(frozen); save()
    try:
        report['source_preflight'] = preflight(); save()
        if mode == 'static':
            ci.ensure(cohort in ['default', 'experimental'], 'static-cohort')
            command = ['cargo', 'clippy', '--locked', '-p', 'marmot-app', '--all-targets', '--features', ci.FEATURES if cohort == 'experimental' else ci.DEFAULT_FEATURES, '--', '-D', 'warnings']
            report.update(cohort=cohort, command=command); save(); started=time.monotonic()
            try: result=subprocess.run(command, capture_output=True, text=True, timeout=1800)
            except subprocess.TimeoutExpired:
                report.update(watchdog_triggered=True, seconds=time.monotonic()-started); raise
            report.update(exit_code=result.returncode, seconds=time.monotonic()-started, **ci.headers(result.stderr))
            report['static_passed']=result.returncode==0 and report['compiler_error_count']==0
        else:
            compilation, cases=ci.compile_cases([POLICY,*SUFFIXES]); report['compilation']=compilation; save()
            ci.ensure(ci.freeze()==frozen, 'compile-input-drift')
            ci.ensure(compilation.get('compile_exit_code')==0 and compilation.get('compiler_error_count')==0 and compilation.get('compiled_fingerprints',{}).get('verified') is True and set(cases)==set([POLICY,*SUFFIXES]), 'compile-or-fingerprint-or-inventory')
            ci.ensure([cases[suffix]['name'] for suffix in SUFFIXES]==NAMES, 'exact-five-inventory')
            ci.ensure(cases[POLICY]['name']==POLICY_NAME,'exact-upstream-policy-inventory')
            report['bodies']=[]
            for suffix in [POLICY,*SUFFIXES]:
                ci.ensure(ci.freeze()==frozen, 'before-body-source-drift')
                before_guard=source_guard()
                case=cases[suffix]; row={'suffix':suffix, 'test':case['name'], 'binary_sha256':case['binary_sha256'], 'source_before_sha256':ci.identity(ci.freeze()), 'source_guard_before':before_guard}; 
                if suffix==POLICY: report['policy_control']=row
                else: report['bodies'].append(row)
                save(); started=time.monotonic()
                try:
                    result=subprocess.run([case['binary'],'--exact',case['name'],'--nocapture','--test-threads=1'],capture_output=True,text=True,timeout=300)
                    raw=result.stdout+result.stderr; row['body_exit_code']=result.returncode
                except subprocess.TimeoutExpired as error:
                    def text(value): return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
                    raw=text(error.stdout)+text(error.stderr); row.update(watchdog_triggered=True, actual_count_unknown=True)
                except Exception as error:
                    row.update(command_exception=type(error).__name__, actual_count_unknown=True); raw=''
                row['body_seconds']=time.monotonic()-started; save()
                try:
                    row.update(body.parse(raw) if suffix==body.CASE else ci.parse_body(raw,suffix))
                    row['named_cases']=re.findall(r'(?m)^test ([A-Za-z_0-9:]+) \.\.\.',re.sub(r'\x1b\[[0-9;]*m','',raw))
                    row['compiler_error_count']=ci.headers(raw)['compiler_error_count']
                    row['control_passed']=bool(policy_passed(row) if suffix==POLICY else passed(row))
                except Exception as error: row.update(parser_exception=type(error).__name__, control_passed=False)
                row['source_after_sha256']=ci.identity(ci.freeze())
                row['source_guard_after']=source_guard()
                row['inputs_pristine']=ci.freeze()==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
                save()
                ci.ensure(row['inputs_pristine'], 'after-body-source-drift')
            report['source_policy_control_passed']=report.get('policy_control',{}).get('control_passed') is True
            report['source_policy_executions']=report.get('policy_control',{}).get('executed_nonignored',0)
            report['actual_runtime_bodies']=report['source_policy_executions']+sum(row.get('executed_nonignored',0) for row in report['bodies'])
            report['actual_counts_complete']=len(report['bodies'])==5 and all(row.get('executed_nonignored')==1 and row.get('ignored')==0 and not row.get('actual_count_unknown') for row in report['bodies'])
            report['all_five_controls_passed']=report['actual_counts_complete'] and all(row.get('control_passed') for row in report['bodies'])
    except Exception as error: report['controller_exception']=type(error).__name__
    finally:
        report.update(inputs_pristine=False, source_after_sha256=None)
        try:
            after=ci.freeze(); report['source_after_sha256']=ci.identity(after)
            report['inputs_pristine']=after==frozen and subprocess.run(['git','diff','--quiet','HEAD']).returncode==0
        except Exception as error: report['final_freeze_exception']=type(error).__name__
        try: report['final_source_guard']=source_guard()
        except Exception as error: report.update(inputs_pristine=False, final_guard_exception=type(error).__name__)
        save()
    raise SystemExit(0 if report['inputs_pristine'] and (report.get('static_passed') if mode=='static' else report['all_five_controls_passed'] and report.get('source_policy_control_passed')) else 1)

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--mode',required=True,choices=['preflight','controls','static']); parser.add_argument('--cohort',choices=['default','experimental']); args=parser.parse_args()
    if args.mode=='preflight': preflight()
    else: run(args.mode,args.cohort)
