"""Balanced Rust call delimiters for identity-wrapper source verification."""
import re
from upstream_completion_ci import ensure

def balanced_end(text, opening):
    ensure(0<=opening<len(text) and text[opening] in '([{','opening-delimiter')
    closing={'(':')','[':']','{':'}'};stack=[closing[text[opening]]];at=opening+1
    while at<len(text):
        if text.startswith('//',at):
            stop=text.find('\n',at+2);at=len(text) if stop<0 else stop+1;continue
        if text.startswith('/*',at):
            depth=1;at+=2
            while at<len(text) and depth:
                if text.startswith('/*',at):depth+=1;at+=2
                elif text.startswith('*/',at):depth-=1;at+=2
                else:at+=1
            ensure(depth==0,'unterminated-block-comment');continue
        raw=re.match(r'(?:br|r)(#*)"',text[at:])
        if raw:
            end='"'+raw[1];stop=text.find(end,at+len(raw[0]));ensure(stop>=0,'unterminated-raw-string');at=stop+len(end);continue
        if text[at]=='"':
            at+=1
            while at<len(text):
                if text[at]=='\\':at+=2
                elif text[at]=='"':at+=1;break
                else:at+=1
            else:ensure(False,'unterminated-string')
            continue
        char=re.match(r"'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'",text[at:])
        if char:at+=len(char[0]);continue
        byte=text[at]
        if byte in closing:stack.append(closing[byte])
        elif byte in ')]}':
            ensure(stack and stack.pop()==byte,'mismatched-delimiter')
            if not stack:return at+1
        at+=1
    ensure(False,'unterminated-delimiter')

def unwrap(text, allowed, marker='ingest_phase_future!'):
    at=0;count={key:0 for key in allowed};result=''
    while True:
        found=text.find(marker,at)
        if found<0:result+=text[at:];break
        result+=text[at:found];opening=found+len(marker)
        while opening<len(text) and text[opening].isspace():opening+=1
        end=balanced_end(text,opening);inside=text[opening+1:end-1]
        match=re.match(r'\s*([0-9]+)\s*,',inside);ensure(match is not None,'numeric-phase-prefix');phase=int(match[1]);ensure(phase in allowed,'unreviewed-phase')
        expression=inside[match.end():].strip()
        if expression.endswith(','):expression=expression[:-1].rstrip()
        calls=list(re.finditer(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*\(',expression))
        matched=[]
        from verify_upstream_completion_candidate_source import normalize
        for call in calls:
            if normalize(expression[:call.end()]) in allowed[phase]: matched.append(call)
        ensure(len(matched)==1,'phase-call-association')
        ensure(balanced_end(expression,matched[0].end()-1)==len(expression),'single-original-future-expression')
        count[phase]+=1;result+=expression;at=end
    ensure(all(count.values()),'missing-call-subtree-phase')
    return result,count

def parser_preflight():
    allowed={7:{'actual('}}
    samples=['actual(a(b), C { x: [1,2] })','actual(") ] }", r##"( [ {"##, br#")"#)', "actual(')', b'x', /* ( /* ) */ ] */ nested(1))"]
    for sample in samples:
        value,count=unwrap('before ingest_phase_future!(7, '+sample+',) after',allowed)
        ensure(value=='before '+sample+' after' and count=={7:1},'balanced-positive')
    negative=0
    for text in ['ingest_phase_future!(7, actual(x])','ingest_phase_future!(7, actual("bad))','ingest_phase_future!(7, actual(r#"bad))','ingest_phase_future!(7, actual(/* bad))','ingest_phase_future!(8, actual(x))','ingest_phase_future!(7, other(x))','ingest_phase_future!(7, actual(x); other())','ingest_phase_future!','none']:
        refused=False
        try:unwrap(text,allowed)
        except ValueError:refused=True
        ensure(refused,'balanced-negative');negative+=1
    return {'positive_controls':len(samples),'negative_controls':negative,'actual_product_bodies':0}
