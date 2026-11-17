"""Compile only the generated model and owned driver, never the target DLL."""
from pathlib import Path
import json,os,runpy
import pytest
from aether_re.process import run_bounded

f=runpy.run_path(str(Path(__file__).with_name('test_call_closure.py')))


@pytest.mark.parametrize('block_name',['aether_edge_0','aether_edge_1'])
def test_original_block_names_cannot_be_overwritten_by_phi_edge_blocks(tmp_path,block_name):
    from aether_re.call_closure import reconstruct_direct_call_closure
    export=f['loop_export'](tmp_path)
    data=export.get_unique_function('caller').pcode_ir
    renamed=json.loads(json.dumps(data).replace('"b1"',json.dumps(block_name)))
    f['replace_function'](export,'caller',renamed)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned x;
 for(x=0U;x<4U;++x) {
  struct aether_sparse_memory m={0};struct aether_call_trace c={0};struct aether_call_event events[32]={{0}};
  unsigned long long result;
  m.steps_left=1000ULL;c.events=events;c.event_capacity=32ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  result=aether_recovered(&m,&c,x,5ULL);
  printf("%u %llu %u %u\n",x,result,m.status,c.status);
 }
 return 0;
}
'''
    expected=[[x,5+x*(x-1)//2,0,0] for x in range(4)]
    for actual in compile_and_run(source,tmp_path):assert actual==expected


def test_generated_calls_share_budget_trace_and_poll_failures(tmp_path):
    report=f['result'](tmp_path)
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
static unsigned polls=0U, stop_at=0U, stop_kind=0U;
static int owned_poll(void *ignored) {
    (void)ignored; ++polls;
    return stop_at && polls>=stop_at ? (int)stop_kind : 0;
}
int main(void) {
    unsigned i;
    for(i=0U;i<12U;++i) {
        struct aether_sparse_memory memory={0};
        struct aether_call_event events[4]={{0}};
        struct aether_call_trace calls={0};
        unsigned long long value;
        memory.space_id=0ULL;memory.steps_left=10ULL;
        calls.events=events;calls.event_capacity=4ULL;
        calls.depth_limit=4ULL;calls.call_limit=10ULL;
        polls=0U;stop_at=0U;stop_kind=0U;
        if(i==1U)memory.steps_left=0ULL;
        if(i==2U)memory.steps_left=1ULL;
        if(i==3U)calls.event_capacity=0ULL;
        if(i==4U)calls.event_capacity=1ULL;
        if(i==5U)calls.depth_limit=0ULL;
        if(i==6U)calls.call_limit=0ULL;
        if(i>=7U && i<=9U) {
            calls.poll=owned_poll;
            stop_at=i==9U ? 2U : 1U;
            stop_kind=i==8U ? 2U : 1U;
        }
        if(i==10U)calls.depth=1ULL;
        if(i==11U)calls.calls=11ULL;
        value=aether_recovered(&memory,&calls,5ULL,7ULL);
        printf("%u %llu %u %u %llu %llu %llu %llu %llu %llu %llu\n",i,value,memory.status,calls.status,
            memory.steps_executed,calls.event_count,calls.depth,calls.calls,
            events[0].arguments[0],events[0].arguments[1],events[1].value);
    }
    return 0;
}
'''
    runs=compile_and_run(source,tmp_path)
    expected=[
        [0,12,0,0,4,2,0,1,5,7,12],
        [1,0,2,0,0,0,0,0,0,0,0],
        [2,0,2,0,1,2,0,1,5,7,0],
        [3,0,0,3,1,0,0,0,0,0,0],
        [4,0,0,3,3,1,0,1,5,7,0],
        [5,0,0,2,1,0,0,0,0,0,0],
        [6,0,0,4,1,0,0,0,0,0,0],
        [7,0,0,5,0,0,0,0,0,0,0],
        [8,0,0,6,0,0,0,0,0,0,0],
        [9,0,0,5,1,1,0,1,5,7,0],
        [10,0,0,1,0,0,1,0,0,0,0],
        [11,0,0,1,0,0,0,11,0,0,0],
    ]
    assert all(actual==expected for actual in runs),runs


def compile_and_run(source,tmp_path):
    (tmp_path/'driver.c').write_text(source,encoding='utf-8')
    vcvars=Path(r'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat')
    assert vcvars.is_file(),'installed MSVC fixture compiler is required for this runtime proof'
    environment=os.environ.copy();environment.update(TEMP=str(tmp_path),TMP=str(tmp_path))
    for name in ('CL','_CL_','LINK','_LINK_'):environment.pop(name,None)
    results=[]
    for option in ('Od','O2'):
        command='\n'.join(['@echo off',f'call "{vcvars}" x64 >nul','if errorlevel 1 exit /b %errorlevel%',
            f'cl /nologo /std:c11 /{option} driver.c /Fo:driver_{option}.obj /Fe:driver_{option}.exe /link /INCREMENTAL:NO',
            'if errorlevel 1 exit /b %errorlevel%','exit /b 0'])+'\n'
        script=tmp_path/('build-'+option+'.cmd');script.write_text(command)
        build=run_bounded([str(Path(os.environ['SystemRoot'])/'System32/cmd.exe'),'/d','/c',str(script)],cwd=str(tmp_path),env=environment,timeout=120,memory_limit_mb=2048,output_limit_bytes=4194304,require_process_tree=True)
        (tmp_path/('BUILD_'+option+'.json')).write_text(json.dumps(build,indent=2))
        assert build['returncode']==0 and build['capture_complete'] and build['process_tree_contained'] and not build['timed_out'] and not build['resource_exceeded'],build
        run=run_bounded([str(tmp_path/f'driver_{option}.exe')],cwd=str(tmp_path),env=environment,timeout=30,memory_limit_mb=512,output_limit_bytes=1048576,require_process_tree=True)
        (tmp_path/('RUN_'+option+'.json')).write_text(json.dumps(run,indent=2))
        assert run['returncode']==0 and run['capture_complete'] and run['process_tree_contained'] and not run['timed_out'] and not run['resource_exceeded'],run
        results.append([list(map(int,line.split())) for line in run['stdout'].splitlines()])
    return results


def test_debug_return_adapter_preserves_shared_call_runtime_and_trace(tmp_path):
    import aether_re.pdb_dia as dia
    export=f['make_export'](tmp_path)
    typed=runpy.run_path(str(Path(__file__).with_name('test_pdb_dia_contract.py')))['typed_payload']()
    typed.update(binary_sha256=export.target_sha256,pdb_sha256='c'*64,helper_sha256='d'*64,dia_dll_sha256='e'*64)
    typed['binding']=dict(status='verified',target_identity_bound=True,target_types_bound=True,
        binary_sha256=export.target_sha256,guid=typed['guid'],age=typed['age'])
    typed['validated_payload_sha256']=dia._payload_digest(typed)
    typed['validated_report_sha256']=dia._report_digest(typed)
    report=export.select_reconstruction('caller',debug_report=typed,memory_model='bounded-bytes.v2',
        call_model='bounded-direct-pure-calls.v1')
    adapter=report['debug_return_adapter']
    assert adapter['call_model']==report['call_model']
    assert [p['name'] for p in adapter['runtime_parameters']]==['aether_memory','aether_calls']
    assert adapter['contract']['return_bits']==8 and adapter['call_semantics_proved'] is False
    source=adapter['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned i;const unsigned long long pairs[3][2]={{5ULL,7ULL},{250ULL,7ULL},{4294967295ULL,3ULL}};
 for(i=0U;i<3U;++i) {
  struct aether_sparse_memory m={0};struct aether_call_event events[4]={{0}};struct aether_call_trace c={0};
  unsigned long long value;
  m.steps_left=100ULL;c.events=events;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  value=aether_debug_return(&m,&c,pairs[i][0],pairs[i][1]);
  printf("%u %llu %u %u %llu %llu %llu\n",i,value,m.status,c.status,c.calls,c.event_count,c.depth);
 }
 return 0;
}
'''
    expected=[[0,12,0,0,1,2,0],[1,1,0,0,1,2,0],[2,2,0,0,1,2,0]]
    for actual in compile_and_run(source,tmp_path):assert actual==expected


def test_call_arguments_follow_formals_when_transport_order_is_reversed(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    report=reconstruct_direct_call_closure(f['branch_export'](tmp_path),'caller')
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned x,y;
 for(x=0U;x<5U;++x)for(y=0U;y<5U;++y) {
  struct aether_sparse_memory m={0};struct aether_call_event events[4]={{0}};struct aether_call_trace c={0};
  unsigned long long value;
  m.steps_left=100ULL;c.events=events;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  value=aether_recovered(&m,&c,x,y);
  printf("%u %u %llu %u %u %llu %llu %llu %llu %llu\n",x,y,value,m.status,c.status,m.steps_executed,c.event_count,events[0].operation,events[0].arguments[0],events[0].arguments[1]);
 }
 return 0;
}
'''
    expected=[[x,y,(x-y if x else y-x)&0xffffffff,0,0,6,2,2 if x else 4,x if x else y,y if x else x] for x in range(5) for y in range(5)]
    for actual in compile_and_run(source,tmp_path):assert actual==expected


def loop_oracle(x,budget):
    steps=events=calls=0;acc=5;n=x&3
    def tick():
        nonlocal steps
        if steps>=budget:raise StopIteration
        steps+=1
    try:
        tick();tick()
        for i in range(n+1):
            for _ in range(4):tick()
            if i==n:break
            tick();events+=1;calls+=1
            try:
                tick();value=(acc+i)&0xffffffff;tick()
            except StopIteration:
                events+=1;raise
            events+=1;acc=value;tick();tick()
        tick()
        return [x,budget,acc,0,0,steps,events,0,calls]
    except StopIteration:return [x,budget,0,2,0,steps,events,0,calls]


@pytest.mark.parametrize('private_stack',[False,True])
def test_call_loop_phi_and_partial_faults_match_an_independent_step_oracle(tmp_path,private_stack):
    from aether_re.call_closure import reconstruct_direct_call_closure
    report=reconstruct_direct_call_closure(f['stack_loop_export' if private_stack else 'loop_export'](tmp_path),'caller')
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned x,budget;
 for(x=0U;x<8U;++x)for(budget=0U;budget<=40U;++budget) {
  struct aether_sparse_memory m={0};struct aether_call_event events[16]={{0}};struct aether_call_trace c={0};
  unsigned long long value;
  m.steps_left=budget;c.events=events;c.event_capacity=16ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  value=aether_recovered(&m,&c,x,5ULL);
  printf("%u %u %llu %u %u %llu %llu %llu %llu\n",x,budget,value,m.status,c.status,m.steps_executed,c.event_count,c.depth,c.calls);
 }
 return 0;
}
'''
    expected=[loop_oracle(x,budget) for x in range(8) for budget in range(41)]
    for actual in compile_and_run(source,tmp_path):assert actual==expected


def test_trace_state_from_another_closure_is_not_rebound(tmp_path):
    from copy import deepcopy
    from aether_re.call_closure import reconstruct_direct_call_closure
    export=f['make_export'](tmp_path);first=reconstruct_direct_call_closure(export,'caller')
    callee=deepcopy(export.get_unique_function('callee').pcode_ir);callee['operations'][0]['opcode']='INT_SUB'
    f['replace_function'](export,'callee',callee);second=reconstruct_direct_call_closure(export,'caller')
    words=[int(v,16) for v in second['call_model']['context_words']]
    source=first['structured_c_source']+'\n#include <stdio.h>\nint main(void) {\n'+r'''
 struct aether_sparse_memory m={0};struct aether_call_event events[4]={{0}};struct aether_call_trace c={0};
 unsigned long long value;m.steps_left=10ULL;c.events=events;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;c.context_bound=1U;
'''+''.join(f'c.context[{i}]={word}ULL;\n' for i,word in enumerate(words))+r'''
 value=aether_recovered(&m,&c,5ULL,7ULL);
 printf("%llu %u %u %llu %llu %llu\n",value,m.status,c.status,m.steps_executed,c.event_count,c.depth);
 return 0;
}
'''
    for actual in compile_and_run(source,tmp_path):assert actual==[[0,0,1,0,0,0]]


def test_nested_calls_unwind_depth_and_preserve_partial_trace(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    report=reconstruct_direct_call_closure(f['nested_export'](tmp_path),'caller')
    assert report['status']=='complete' and report['call_model']['observed_call_depth']==2,report
    source=report['structured_c_source']+r'''
#include <stdio.h>
static unsigned polls;
static int nested_poll(void *unused){(void)unused;return ++polls>=3U ? 2 : 0;}
int main(void) {
 unsigned i;
 for(i=0U;i<7U;++i) {
  struct aether_sparse_memory m={0};struct aether_call_event e[8]={{0}};struct aether_call_trace c={0};
  unsigned long long value;m.steps_left=10ULL;c.events=e;c.event_capacity=8ULL;c.depth_limit=4ULL;c.call_limit=10ULL;polls=0U;
  if(i==1U)c.depth_limit=1ULL;
  if(i==2U)c.call_limit=1ULL;
  if(i==3U)c.event_capacity=2ULL;
  if(i==4U)c.event_capacity=3ULL;
  if(i==5U)m.steps_left=2ULL;
  if(i==6U)c.poll=nested_poll;
  value=aether_recovered(&m,&c,5ULL,7ULL);
  printf("%u %llu %u %u %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",i,value,m.status,c.status,m.steps_executed,c.event_count,c.depth,c.calls,
      e[0].kind,e[1].kind,e[2].kind,e[3].kind,e[2].memory_status,e[3].memory_status);
 }
 return 0;
}
'''
    expected=[
        [0,12,0,0,6,4,0,2,1,1,2,2,0,0],
        [1,0,0,2,2,1,0,1,1,0,0,0,0,0],
        [2,0,0,4,2,1,0,1,1,0,0,0,0,0],
        [3,0,0,3,4,2,0,2,1,1,0,0,0,0],
        [4,0,0,3,5,3,0,2,1,1,2,0,0,0],
        [5,0,2,0,2,4,0,2,1,1,2,2,2,2],
        [6,0,0,6,2,2,0,2,1,1,0,0,0,0],
    ]
    for actual in compile_and_run(source,tmp_path):assert actual==expected


def test_void_calls_propagate_faults_without_a_fabricated_return_value(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    report=reconstruct_direct_call_closure(f['void_export'](tmp_path),'caller')
    assert report['status']=='complete' and report['return_bits']==0,report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned budget;
 for(budget=0U;budget<=4U;++budget) {
  struct aether_sparse_memory m={0};struct aether_call_event e[4]={{0}};struct aether_call_trace c={0};
  m.steps_left=budget;c.events=e;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  aether_recovered(&m,&c,5ULL,7ULL);
  printf("%u %u %u %llu %llu %llu %llu %llu %llu\n",budget,m.status,c.status,m.steps_executed,c.event_count,c.depth,c.calls,e[1].value,e[1].memory_status);
 }
 return 0;
}
'''
    expected=[[budget,0 if budget==4 else 2,0,budget,2 if budget else 0,0,1 if budget else 0,0,2 if budget in (1,2) else 0] for budget in range(5)]
    for actual in compile_and_run(source,tmp_path):assert actual==expected
