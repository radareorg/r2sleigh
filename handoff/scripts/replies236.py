import subprocess,sys
sha=dict(a.split('=') for a in sys.argv[1:])
R = {
"PRRT_kwDOQ4ZAfM6sHMN3": f"Kept, with the inference made visible in {sha['p9doc']} (#231). The accesses prove a layout: which bytes are read and written, at which widths. Spelling it as a structure is a choice. Your serialized buffer read at +0 as u64 and at +8 as u32 compiles to the same loads through the struct, so the rendered program keeps its semantics, and whether the source declared a structure is unprovable either way. The tag `fcn_<entry>_arg<slot>` marks the type as inferred, and the proof line now says \"1 structure laid out from a parameter's accesses\". The ADR states what is proven and what is chosen, and records that P9b's member spelling must stay alias-safe under strict aliasing.",
"PRRT_kwDOQ4ZAfM6sHMN8": f"Fixed in {sha['p9ops']} (#231). Any memory operation other than a plain RAM load or store that the parameter feeds now refuses the layout as `Unmodelled`, and its output is not followed. Test: two plain fields of different widths beside a `LoadLinked` at +16 refuse; the old walk laid out a structure.",
"PRRT_kwDOQ4ZAfM6sHMOB": f"Right about the stated bound: it is one walk per formal, O(P · (values + uses)), and the ADR now says so ({sha['p9doc']}). Measured on contabo with and without P9, 5 runs each: 0pack `0x58e3d0`, `0x62ecf0` and pumasim `0x23fdf0` all run 5.0 to 6.4 s either way, with +1 to 2.5% RSS. One pass over `fixpoint::sparse` with a u64 parameter mask is recorded in the ROADMAP's P9 row, for when a function whose formals share closures shows the cost.",
"PRRT_kwDOQ4ZAfM6sHNMR": f"Checked in {sha['tail']} (#234). Correlation and the machine context name a tail call only at a terminal `Branch`, so the advisory site is dropped, as you say. The tail arm does not then return the state from before the branch: `test edi, edi; jne g; mov eax, 1; ret` refuses at the control certificate (edge mismatch). A negative test pins that refusal. Rendering `if (c) return g(...)` needs the tail arm as an exit boundary in the CFG, the correlation and the machine context, which the ROADMAP's P7 row records.",
"PRRT_kwDOQ4ZAfM6sHNRc": f"Fixed in {sha['lane']} (#235). The check is now `float_lane(slot, storage)` and requires the slot's offset, as `SourceResultCarriers::holds` does. Inline test: the low 8 and 4 bytes are a float result, and the upper qword, a 2-byte lane and a missing slot are not.",
}
ok=0
for tid,body in R.items():
    q='mutation($t:ID!,$b:String!){addPullRequestReviewThreadReply(input:{pullRequestReviewThreadId:$t,body:$b}){comment{id}}}'
    r=subprocess.run(['gh','api','graphql','-f',f'query={q}','-f',f't={tid}','-f',f'b={body}'],capture_output=True,text=True)
    if r.returncode!=0: print('REPLY FAIL',tid,r.stderr[:200]); continue
    q2='mutation($t:ID!){resolveReviewThread(input:{threadId:$t}){thread{isResolved}}}'
    r2=subprocess.run(['gh','api','graphql','-f',f'query={q2}','-f',f't={tid}'],capture_output=True,text=True)
    if '"isResolved":true' not in r2.stdout: print('RESOLVE FAIL',tid,r2.stdout[:200]); continue
    ok+=1
print('done',ok,'of',len(R))
