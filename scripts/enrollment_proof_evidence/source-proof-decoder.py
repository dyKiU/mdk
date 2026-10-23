"""Closed source-proof decoder; exact function from reviewed evidence filter ee7c3025."""
import re
U = 2**64 - 1

def source_proof_dec(raw):
 if len(raw)>8192:raise ValueError()
 ts=re.findall(r'(?:0|[1-9][0-9]{0,19})|[A-Za-z_][A-Za-z_0-9]*|[\[\](),{}:]',raw)
 if ''.join(ts)!=re.sub(r'\s','',raw):raise ValueError()
 fields={'SourceProofSummary':['source_slot','recipient_slot','request_records','prepared','acknowledged','later_attempts','later_distinct_attempts','unbound_preparations','raw','event','nonce','authentication','dispatch','owned','prepared_ms','sdk_ack_ms','queue','ack_conflict','overflow','ambiguous','partial'],'ProofQueueFacts':['capture_ms','outer','content','same_receiver','outer_equals_content'],'ProofQueueObservation':['disposition','placement','depths','dequeued','accepted_ms','dequeued_ms','invalid']};p=0
 def take(t):
  nonlocal p
  if p>=len(ts) or ts[p]!=t:raise ValueError()
  p+=1
 def val(dep=0):
  nonlocal p
  if dep>12 or p>=len(ts):raise ValueError()
  t=ts[p];p+=1
  if t in fields:
   take('{');d={}
   for n,k in enumerate(fields[t]):
    take(k);take(':');d[k]=val(dep+1)
    if n+1<len(fields[t]):take(',')
   take('}');return d
  if t in ('[','('):
   end=']' if t=='[' else ')';a=[]
   while p<len(ts) and ts[p]!=end:
    a.append(val(dep+1))
    if len(a)>17:raise ValueError()
    if p<len(ts) and ts[p]==',':p+=1
    elif p>=len(ts) or ts[p]!=end:raise ValueError()
   take(end);return a
  if t=='Some':
   take('(');a=val(dep+1);take(')');return {'some':a}
  if t=='None':return None
  if t in ('true','false'):return t=='true'
  if t.isdigit() and int(t)<=U:return int(t)
  raise ValueError()
 d=val()
 if p!=len(ts):raise ValueError()
 def uint(x):return type(x)==int and 0<=x<=U
 def array(a,n):return type(a)==list and len(a)==n and all(uint(x) for x in a)
 def opt(x,pred):return x is None or type(x)==dict and list(x)==['some'] and pred(x['some'])
 def obs(x):
  return type(x)==dict and list(x)==fields['ProofQueueObservation'] and array(x['disposition'],8) and array(x['placement'],6) and opt(x['depths'],lambda y:array(y,2) and all(z<=1025 for z in y)) and uint(x['dequeued']) and opt(x['accepted_ms'],uint) and opt(x['dequeued_ms'],uint) and type(x['invalid'])==bool
 def facts(x):return type(x)==dict and list(x)==fields['ProofQueueFacts'] and opt(x['capture_ms'],uint) and opt(x['outer'],obs) and opt(x['content'],obs) and opt(x['same_receiver'],lambda y:type(y)==bool) and type(x['outer_equals_content'])==bool
 if type(d)!=dict or list(d)!=fields['SourceProofSummary'] or not all(uint(d[k]) for k in ['source_slot','recipient_slot','request_records','prepared','acknowledged','later_attempts','later_distinct_attempts','unbound_preparations','raw','event','nonce']) or not array(d['authentication'],5) or not array(d['dispatch'],5) or not array(d['owned'],3) or not opt(d['prepared_ms'],uint) or not opt(d['sdk_ack_ms'],uint) or not opt(d['queue'],facts) or not all(type(d[k])==bool for k in ['ack_conflict','overflow','ambiguous','partial']):raise ValueError()
 return d
