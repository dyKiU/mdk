"""Authored controls. Run only remotely after source review; no API/product invocation."""
import ast,re
from pathlib import Path

def main():
 source=(Path(__file__).parent/'source-proof-decoder.py').read_text()
 tree=ast.parse(source)
 defs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='source_proof_dec']
 assert len(defs)==1
 ns={'re':re,'U':2**64-1};exec(compile(ast.Module(body=defs,type_ignores=[]),'<closed-reducer-controls>','exec'),ns)
 parse=ns['source_proof_dec']
 valid='SourceProofSummary { source_slot: 0, recipient_slot: 2, request_records: 1, prepared: 1, acknowledged: 1, later_attempts: 0, later_distinct_attempts: 0, unbound_preparations: 0, raw: 1, event: 1, nonce: 1, authentication: [1, 0, 0, 0, 0], dispatch: [1, 0, 0, 0, 0], owned: [1, 1, 1], prepared_ms: Some(0), sdk_ack_ms: Some(1), queue: None, ack_conflict: false, overflow: false, ambiguous: false, partial: true }'
 unknown=valid.replace('request_records: 1','request_records: 0').replace('prepared: 1','prepared: 0').replace('acknowledged: 1','acknowledged: 0').replace('Some(0)','None').replace('Some(1)','None')
 maximum=valid.replace('later_attempts: 0','later_attempts: 18446744073709551615').replace('overflow: false','overflow: true')
 for row in [valid,unknown,maximum]:assert type(parse(row))==dict
 invalid=[valid+' PRIVATE',valid.replace('SourceProofSummary','Summary'),valid.replace('source_slot: 0','source_slot: -1'),valid.replace('source_slot: 0','source_slot: true'),valid.replace('prepared: 1','prepared: 18446744073709551616'),valid.replace('prepared: 1','prepared: 01'),valid.replace('authentication: [1, 0, 0, 0, 0]','authentication: [1, 0, 0, 0]'),valid.replace('dispatch: [1, 0, 0, 0, 0]','dispatch: [1, 0, 0, 0, 0, 0]'),valid.replace('owned: [1, 1, 1]','owned: [1, 1, false]'),valid.replace('Some(0)','Some(-1)'),valid.replace('Some(1)','Some(true)'),valid.replace('queue: None','queue: Some(Private)'),valid.replace('partial: true','partial: None'),valid.replace('partial: true','partial: 1'),valid.replace('nonce: 1,','nonce: 1, private: 0,'),valid.replace('nonce: 1,',''),valid.replace('event: 1, nonce: 1','nonce: 1, event: 1'),valid.replace('Some(0)','Some(Some(0))'),valid.replace('ack_conflict: false','ack_conflict: FALSE'),valid.replace('unbound_preparations: 0','unbound_preparations: "private"'),valid+' '*8193]
 for row in invalid:
  try:parse(row)
  except (ValueError,IndexError):pass
  else:raise AssertionError('closed-source-proof-negative-accepted')
 print({'decoder_positive':3,'decoder_negative':len(invalid),'product_bodies':0})
if __name__=='__main__':main()
