#!/usr/bin/env python3
"""Remote source guard: exact public proof memo, never authorization reuse."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
BASE = '9eae9ce1069ecfd25b6a7da24e9de6a0bce95f59'
PREFIX = 'crates/cgka-engine/src/'
def old(name): return subprocess.check_output(['git','show',BASE+':'+PREFIX+name],text=True)
def current(name): return Path(PREFIX+name).read_text()
def compact(value): return re.sub(r'\s+', '', value).replace(',)', ')')
def function(source, name):
    start = re.search(r'(?m)^(?:pub(?:\(crate\))? )?fn '+re.escape(name)+r'(?:<|\()',source).start()
    opening = source.index('{',start)
    depth=1
    end=opening+1
    while depth:
        depth += (source[end]=='{') - (source[end]=='}')
        end += 1
    return source[start:opening],source[opening:end]
def equal_body(original, updated): assert compact(original)==compact(updated), 'fresh validation or error order changed'
a = old('account_identity_proof.rs'); b = current('account_identity_proof.rs')
for name in ['verify_proof_signature','validate_proof_bindings','validate_current_timestamp','decode_legacy_proof']:
    assert function(a,name)==function(b,name), name+' must stay byte exact'
for kind in ['legacy','current']:
    body=function(b,'validate_'+kind+'_proof_with_verifier')[1]
    body=body.replace('verify(&proof.request, &proof.signature)','verify_proof_signature(&proof.request, &proof.signature)').replace('verify(&request, &signature)','verify_proof_signature(&request, &signature)')
    equal_body(function(a,'validate_'+kind+'_proof')[1],body)
    assert '&verify_proof_signature' in function(b,'validate_'+kind+'_proof')[1]
body=function(b,'validate_leaf_account_identity_proof_with_verifier')[1]
for kind,args in [('legacy','raw.0.as_slice(), leaf, account_identity, ciphersuite'),('current','raw, leaf, account_identity, ciphersuite')]:
    # Whitespace-insensitive counterpart handles canonical Rust formatting.
    stripped=compact(body)
    # Match only the two explicit cold/memo dispatch arms.
    stripped=re.sub(r'matchverifier\{Some\(verify\)=>validate_'+kind+r'_proof_with_verifier\(.*?\)\?,None=>validate_'+kind+r'_proof\(.*?\)\?,\}',compact('validate_'+kind+'_proof('+args+')?;'),stripped)
    body=stripped
# Replacement includes semicolon already present after original calls, whereas match has none.
equal_body(function(a,'validate_leaf_account_identity_proof')[1],body)
body=function(b,'validate_leaf_account_identity_proof_for_member_with_verifier')[1]
body=re.sub(r'let profile = match verifier \{.*?\n    \};', 'let profile = validate_leaf_account_identity_proof(leaf, ciphersuite)?;',body,flags=re.S)
equal_body(function(a,'validate_leaf_account_identity_proof_for_member')[1],body)
assert 'None)' in compact(function(b,'validate_leaf_account_identity_proof_for_member')[1])
a=old('private_roster_settlement.rs'); b=current('private_roster_settlement.rs')
body=function(b,'completed_round_for_predecessor_tree_with_verifier')[1]
body=body.replace('validate_leaf_account_identity_proof_for_member_with_verifier','validate_leaf_account_identity_proof_for_member')
body=re.sub(r'("private completed predecessor",)\s*verifier,',r'\1',body)
equal_body(function(a,'completed_round_for_predecessor_tree')[1],body)
assert 'actual,None)' in compact(function(b,'completed_round_for_predecessor_tree')[1])
body=compact(function(b,'completed_round_for_tree_with_verifier')[1]).replace('completed_round_for_predecessor_tree_with_verifier(storage,group,actual,verifier)','completed_round_for_predecessor_tree(storage,group,actual)')
equal_body(function(a,'completed_round_for_tree')[1],body)
# The sole non-cold inlet remains inside the existing pinned read snapshot.
assert compact(b).count('self.private_proof_signatures.verify(request,signature)')==1
assert b.count('Some(&verify)')==1
getter_start=b.index('    pub fn validated_settled_device_roster(')
getter_end=b.index('    #[cfg(test)]',getter_start)
getter=b[getter_start:getter_end]
assert 'self.storage.with_read_snapshot' in getter and 'MlsGroup::load' in getter
assert 'completed_round_for_tree_with_verifier' in getter
assert 'completed_round_for_tree_with_verifier(storage,group,actual,None)' in compact(b)
old_getter=a[a.index('    pub fn validated_settled_device_roster('):a.index('    #[cfg(test)]',a.index('    pub fn validated_settled_device_roster('))]
normalized=re.sub(r'\s*let verify\s*=\s*.*?\};\n', '', getter, flags=re.S)
normalized=compact(normalized).replace('completed_round_for_tree_with_verifier(storage,group,&actual,Some(&verify))','completed_round_for_tree(storage,group,&actual)')
equal_body(old_getter,normalized)
engine=current('engine.rs')
engine=re.sub(r'    #\[cfg\(feature = "experimental-device-sync"\)\]\n    pub\(crate\) private_proof_signatures:.*?ProofSignatureMemo,\n', '',engine,flags=re.S)
engine=re.sub(r'            #\[cfg\(feature = "experimental-device-sync"\)\]\n            private_proof_signatures:.*?ProofSignatureMemo::default\(\),\n', '',engine,flags=re.S)
equal_body(old('engine.rs'),engine)
allowed={PREFIX+name for name in ['account_identity_proof.rs','engine.rs','private_roster_settlement.rs','account_identity_proof_memo.rs','account_identity_proof_memo_tests.rs']}
for name in subprocess.check_output(['git','ls-files'],text=True).splitlines():
    if (name.startswith('crates/') or name in ['Cargo.lock','Cargo.toml','.cargo/config.toml','.config/nextest.toml']) and name not in allowed:
        assert Path(name).read_bytes()==subprocess.check_output(['git','show',BASE+':'+name]), 'unrelated source/config changed: '+name
memo=current('account_identity_proof_memo.rs')
assert 'const CAPACITY: usize = 128;' in memo and 'const MAX_MLS_KEY_BYTES: usize = 128;' in memo
assert 'entry.request==*request&&entry.signature==*signature' in compact(memo)
assert 'verify_proof_signature(request, signature)?;' in memo
assert 'Debug' not in memo and 'Serialize' not in memo and 'thread_local' not in memo and 'Arc<' not in memo
report={'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':BASE,'unchanged_default_signature_verifier':True,'fresh_leaf_binding_and_error_order_preserved':True,'general_completed_wrappers_cold':True,'sole_memo_inlet_existing_pinned_roster_snapshot':True,'unchanged_app_deadlines_json_faults_and_sql_memo':True,'source_preflight_passed':True,'qualification_passed':False,'memo_sha256':hashlib.sha256(memo.encode()).hexdigest()}
Path('public-proof-memo-source.json').write_text(json.dumps(report,indent=2)+'\n')
