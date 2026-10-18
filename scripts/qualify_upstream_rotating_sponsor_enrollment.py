#!/usr/bin/env python3
"""Frozen rotating-sponsor product cohort over unchanged sixteen-case ACK qualification."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import qualify_upstream_request_retry_ack as ack

BASE = '7df32c24236c4a381ea3d6439003618bcae64ab5'
SELF = 'scripts/qualify_upstream_rotating_sponsor_enrollment.py'
WORKFLOW = '.github/workflows/experimental-sync-ci.yml'
REF = 'refs/heads/ci/upstream-rotating-sponsor-enrollment-20261018'
BEGIN = '  # ROTATING_SPONSOR_ENROLLMENT_JOBS_BEGIN\n'
END = '  # ROTATING_SPONSOR_ENROLLMENT_JOBS_END\n\n'
OPTIONS = 'options: [rotating-enrollment-preflight, rotating-enrollment-controls, '
OUT = Path('rotating-sponsor-enrollment-evidence')
ensure = ack.ensure


def source_guard():
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    ensure(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='dyKiU/mdk'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and os.environ.get('GITHUB_SHA')==head
        and os.environ.get('GITHUB_REF')==REF and os.environ.get('GITHUB_WORKFLOW_REF')=='dyKiU/mdk/'+WORKFLOW+'@'+REF
        and os.environ.get('UPSTREAM_ROTATING_ENROLLMENT_BASELINE')==BASE,'exact-owned-final-cohort-workflow')
    ensure(os.environ.get('CARGO_INCREMENTAL')=='1' and os.environ.get('CARGO_BUILD_JOBS')=='2'
        and os.environ.get('RUST_MIN_STACK')=='4194304'
        and all(os.environ.get(k)=='0' for k in ['CARGO_PROFILE_DEV_DEBUG','CARGO_PROFILE_TEST_DEBUG'])
        and all(not os.environ.get(k) for k in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_BOOTSTRAP','CARGO_PROFILE_DEV_OPT_LEVEL','CARGO_PROFILE_TEST_OPT_LEVEL']),'exact-final-build-cohort')
    subprocess.run(['git','merge-base','--is-ancestor',BASE,head],check=True)
    ensure(subprocess.run(['git','diff','--quiet','HEAD']).returncode==0,'initial-tracked-pristine')
    baseline={}
    for entry in subprocess.check_output(['git','ls-tree','-r','-z',BASE]).split(b'\0'):
        if entry:
            metadata,name=entry.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            ensure(kind=='blob' and mode in {'100644','100755','120000'},'ordinary-final-baseline-layout')
            baseline[os.fsdecode(name)]=(mode,blob)
    current=ack.layout()
    ensure(SELF not in baseline and set(current)==set(baseline)|{SELF},'whole-final-cohort-inventory')
    for name,value in current.items():
        mode,blob=baseline.get(name,('100644',None))
        ensure(value['git_mode']==mode and value['symlink']==(mode=='120000')
            and (value['symlink'] or value['actual_executable']==(mode=='100755')),'whole-final-cohort-mode')
        data=os.fsencode(os.readlink(name)) if value['symlink'] else Path(name).read_bytes()
        if name==WORKFLOW:
            text=data.decode();ensure(text.count(BEGIN)==text.count(END)==text.count(OPTIONS)==1,'one-isolated-final-workflow-overlay')
            before,rest=text.split(BEGIN);_,after=rest.split(END)
            data=(before+after).replace(OPTIONS,'options: [',1).encode()
        if blob is not None: ensure(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==blob,'exact-final-source:'+name)
    ensure(set(subprocess.check_output(['git','ls-files','--others','--exclude-standard'],text=True).splitlines()) <= {str(OUT/'result.json')},'no-untracked-source-overlay')
    ensure(len(ack.CASES)==16 and len({row[0] for row in ack.CASES})==16,'unchanged-sixteen-case-definition')
    return {'source':head,'reviewed_final_baseline':BASE,'all_product_tests_helpers_contents_and_modes_exact':True,
        'historical_ACK_controller_preserved':True,'historical_ACK_source_guard_invoked':False,
        'explicit_wrapper_guard_substitution':True,'historical_runtime_evidence_reused':False,
        'storage_rotating_sponsor_GREEN_is_separate_required_evidence':True,'original_sixteen_including_three_required_serial_stress_cases_preserved':True,'five_device_owner_fixture_not_in_this_lane':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight',action='store_true')
    parser.add_argument('--mode',choices=['full','static'],default='full')
    parser.add_argument('--cohort',choices=['default','experimental'])
    args=parser.parse_args()
    ensure(args.mode!='static' or args.cohort in {'default','experimental'},'explicit-static-cohort')
    # These are the only substitutions. Historical case/parser/compile/runtime,
    # feature, count, binary, closure and finally-pristine functions stay intact.
    ack.source_guard=source_guard
    ack.OUT=OUT
    ack.main(args)


if __name__=='__main__':
    main()
