"""Native validation of the third bounded state, using owned drivers only."""
from pathlib import Path
import runpy
import pytest

helpers=runpy.run_path(str(Path(__file__).with_name('test_call_closure_runtime.py')))


def test_operation_trace_fences_context_steps_shape_and_capacity(tmp_path):
    from aether_re.ghidra_pcode_c import _SPARSE_MEMORY_RUNTIME
    from aether_re.call_runtime import CALL_RUNTIME
    from aether_re.effect_trace import EFFECT_RUNTIME
    source=_SPARSE_MEMORY_RUNTIME+CALL_RUNTIME+EFFECT_RUNTIME+r'''
#include <stdio.h>
int main(void) {
 unsigned i;
 for(i=0U;i<9U;++i) {
  struct aether_sparse_memory m={0};struct aether_call_trace c={0};
  struct aether_call_event ce[4]={{0}};
  struct aether_sparse_event prior_memory_event[1]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[4]={{0}};
  int admitted,appended=0;
  m.steps_left=100ULL;c.events=ce;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  e.events=ee;e.event_capacity=4ULL;
  if(i==1U)e.event_capacity=0ULL;
  if(i==2U)e.event_capacity=1000001ULL;
  if(i==3U)e.events=0;
  if(i==4U){m.steps_executed=1ULL;m.steps_left=99ULL;}
  if(i==8U){m.events=prior_memory_event;m.event_capacity=1ULL;m.event_count=1ULL;}
  aether_call_entry(&c,1U,1ULL,2ULL,3ULL,4ULL);
  admitted=aether_effect_trace_entry(&e,&m,&c,1U);
  if(admitted) {
   aether_sparse_memory_step(&m);
   if(i==5U)aether_sparse_memory_step(&m);
   appended=aether_effect_trace_append(&e,&m,&c,0ULL,i==6U?900ULL:i==7U?511ULL:7ULL,i==7U?2ULL:1ULL);
  }
  printf("%u %d %d %u %u %u %llu %llu %llu %llu %llu %llu\n",i,admitted,appended,m.status,c.status,e.status,m.steps_executed,e.event_count,e.last_step,ee[0].kind,ee[0].function,ee[0].operation);
 }
 return 0;
}
'''
    expected=[[0,1,1,0,0,0,1,1,1,1,0,7],
        [1,1,0,0,0,2,1,0,0,0,0,0],
        [2,0,0,0,0,1,0,0,0,0,0,0],
        [3,0,0,0,0,1,0,0,0,0,0,0],
        [4,0,0,0,0,1,1,0,0,0,0,0],
        [5,1,0,0,0,1,2,0,0,0,0,0],
        [6,1,0,0,0,1,1,0,0,0,0,0],
        [7,1,1,0,0,0,1,1,1,2,0,511],
        [8,0,0,0,0,1,0,0,0,0,0,0]]
    for actual in helpers['compile_and_run'](source,tmp_path):assert actual==expected


def test_caller_reads_before_and_after_aliased_callee_write_with_ordered_provenance(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    report=reconstruct_direct_call_closure(fixture['alias_export'](tmp_path),'caller',call_model=fixture['MODEL'])
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned a,b,j,index=0U;const unsigned long long values[8]={0ULL,1ULL,2ULL,255ULL,65535ULL,2147483647ULL,2147483648ULL,4294967295ULL};
 const unsigned long long deltas[5]={0ULL,1ULL,3ULL,255ULL,4294967295ULL};
 for(a=0U;a<8U;++a)for(b=0U;b<5U;++b,++index) {
  unsigned char bytes[4],permissions[4]={3U,3U,3U,3U},initialized[4]={1U,1U,1U,1U};
  struct aether_sparse_region region={bytes,permissions,initialized,4096ULL,4ULL};
  struct aether_sparse_memory m={0};struct aether_sparse_event me[8]={{0}};
  struct aether_call_trace c={0};struct aether_call_event ce[4]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[32]={{0}};
  unsigned long long result,stored=0ULL;
  for(j=0U;j<4U;++j)bytes[j]=(unsigned char)(values[a]>>(j*8U));
  m.regions=&region;m.region_count=1ULL;m.steps_left=100ULL;m.events=me;m.event_capacity=8ULL;
  c.events=ce;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  e.events=ee;e.event_capacity=32ULL;
  result=aether_recovered(&m,&c,&e,4096ULL,deltas[b]);
  for(j=0U;j<4U;++j)stored|=(unsigned long long)bytes[j]<<(j*8U);
  printf("0 %u %llu %llu %llu %llu %u %u %u %llu %llu %llu %llu\n",index,values[a],deltas[b],result,stored,m.status,c.status,e.status,m.steps_executed,m.event_count,c.event_count,e.event_count);
  for(j=0U;j<m.event_count;++j)printf("1 %u %u %llu %llu %llu %u %u\n",index,j,me[j].operation,me[j].address,me[j].value,me[j].width,me[j].kind);
  for(j=0U;j<c.event_count;++j)printf("2 %u %u %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",index,j,ce[j].caller,ce[j].callee,ce[j].operation,ce[j].kind,ce[j].memory_status,ce[j].value,ce[j].argument_count,ce[j].arguments[0],ce[j].arguments[1]);
  for(j=0U;j<e.event_count;++j)printf("3 %u %u %llu %llu %llu %llu %llu %llu\n",index,j,ee[j].step,ee[j].function,ee[j].operation,ee[j].kind,ee[j].memory_events_before,ee[j].call_events_before);
 }
 return 0;
}
'''
    expected=[];positions=[(0,0,0,0),(0,1,1,0),(1,0,1,1),(1,1,2,1),
        (1,2,2,1),(1,3,3,1),(0,2,3,2),(0,3,4,2),(0,4,4,2),(0,5,4,2),(0,6,4,2),(0,7,4,2)]
    index=0
    for old in (0,1,2,255,65535,2147483647,2147483648,4294967295):
        for delta in (0,1,3,255,4294967295):
            new=(old+delta)&0xffffffff;answer=(7*old+4*new)&0xffffffff
            expected.append([0,index,old,delta,answer,new,0,0,0,12,4,2,12])
            for j,(token,value,kind) in enumerate([(0,old,0),(1024,old,0),(1026,new,1),(2,new,0)]):
                expected.append([1,index,j,token,4096,value,4,kind])
            expected.extend([[2,index,0,0,1,1,1,0,0,2,4096,delta],[2,index,1,0,1,1,2,0,new,0,0,0]])
            for j,(function,operation,memory_before,calls_before) in enumerate(positions):
                expected.append([3,index,j,j+1,function,operation,1,memory_before,calls_before])
            index+=1
    for actual in helpers['compile_and_run'](source,tmp_path):assert actual==expected


def test_generated_effect_calls_share_bytes_and_stop_before_untraced_store(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    report=reconstruct_direct_call_closure(fixture['memory_export'](tmp_path),'caller',call_model=fixture['MODEL'])
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned i;
 for(i=0U;i<4U;++i) {
  unsigned char bytes[4]={2U,0U,0U,0U},permissions[4]={3U,3U,3U,3U},initialized[4]={1U,1U,1U,1U};
  struct aether_sparse_region region={bytes,permissions,initialized,4096ULL,4ULL};
  struct aether_sparse_memory m={0};struct aether_sparse_event me[4]={{0}};
  struct aether_call_trace c={0};struct aether_call_event ce[4]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[16]={{0}};
  unsigned long long value;
  m.regions=&region;m.region_count=1ULL;m.steps_left=100ULL;m.events=me;m.event_capacity=4ULL;
  c.events=ce;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  e.events=ee;e.event_capacity=i==0U?16ULL:i==1U?3ULL:i==2U?1ULL:0ULL;
  value=aether_recovered(&m,&c,&e,4096ULL,3ULL);
  printf("%u %llu %u %u %u %u %llu %llu %llu %llu %llu %llu %llu\n",i,value,bytes[0],m.status,c.status,e.status,m.steps_executed,m.event_count,c.event_count,c.depth,e.event_count,e.last_step,me[0].operation);
 }
 return 0;
}
'''
    expected=[[0,5,5,0,0,0,6,2,2,0,6,6,1024],
        [1,0,2,0,1,2,4,1,1,0,3,3,1024],
        [2,0,2,0,1,2,2,0,1,0,1,1,0],
        [3,0,2,0,0,2,1,0,0,0,0,0,0]]
    for actual in helpers['compile_and_run'](source,tmp_path):assert actual==expected


def test_effect_calls_preserve_partial_bytes_and_all_failure_channels(tmp_path):
    from aether_re.call_closure import reconstruct_direct_call_closure
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    report=reconstruct_direct_call_closure(fixture['memory_export'](tmp_path),'caller',call_model=fixture['MODEL'])
    assert report['status']=='complete',report
    source=report['structured_c_source']+r'''
#include <stdio.h>
static unsigned polls=0U,stop_kind=1U;
static int owned_effect_poll(void *unused) {(void)unused;return ++polls>=4U?(int)stop_kind:0;}
int main(void) {
 unsigned i;
 for(i=0U;i<20U;++i) {
  unsigned char bytes[4]={2U,0U,0U,0U},permissions[4]={3U,3U,3U,3U},initialized[4]={1U,1U,1U,1U};
  struct aether_sparse_region region={bytes,permissions,initialized,4096ULL,4ULL};
  struct aether_sparse_memory m={0};struct aether_sparse_event me[4]={{0}};
  struct aether_call_trace c={0};struct aether_call_event ce[4]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[32]={{0}};
  unsigned long long value;
  m.regions=&region;m.region_count=1ULL;m.steps_left=100ULL;m.events=me;m.event_capacity=4ULL;
  c.events=ce;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  e.events=ee;e.event_capacity=32ULL;
  if(i==1U)permissions[0]=1U;
  if(i==2U)initialized[0]=0U;
  if(i==3U)region.length=3ULL;
  if(i==4U)m.steps_left=3ULL;
  if(i==5U)m.event_capacity=1ULL;
  if(i==6U)c.event_capacity=1ULL;
  if(i==7U || i==8U){polls=0U;stop_kind=i==8U?2U:1U;c.poll=owned_effect_poll;}
  if(i==10U)c.depth_limit=0ULL;
  if(i==11U)c.call_limit=0ULL;
  if(i==12U)c.event_capacity=0ULL;
  if(i==13U)m.space_id=1ULL;
  if(i==15U){e.context_bound=1U;e.context[0]=42ULL;}
  if(i==16U)m.steps_left=0ULL;
  if(i==17U){m.steps_executed=1ULL;m.steps_left=99ULL;}
  if(i==18U)e.event_capacity=1ULL;
  if(i==19U)e.event_capacity=5ULL;
  value=aether_recovered(&m,&c,i==9U?0:&e,i==14U?4097ULL:4096ULL,3ULL);
  printf("%u %llu %u %u %u %u %llu %llu %llu %llu %llu %llu %llu\n",i,value,bytes[0],m.status,c.status,e.status,m.steps_executed,m.event_count,c.event_count,c.calls,c.depth,e.event_count,e.last_step);
 }
 return 0;
}
'''
    expected=[[0,5,5,0,0,0,6,2,2,1,0,6,6],
        [1,0,2,5,0,0,4,1,2,1,0,4,4],
        [2,0,2,6,0,0,2,0,2,1,0,2,2],
        [3,0,2,4,0,0,2,0,2,1,0,2,2],
        [4,0,2,2,0,0,3,1,2,1,0,3,3],
        [5,0,2,7,0,0,4,1,2,1,0,4,4],
        [6,0,5,0,3,0,5,2,1,1,0,5,5],
        [7,0,2,0,5,0,3,1,1,1,0,3,3],
        [8,0,2,0,6,0,3,1,1,1,0,3,3],
        [9,0,2,0,1,0,0,0,0,0,0,0,0],
        [10,0,2,0,2,0,1,0,0,0,0,1,1],
        [11,0,2,0,4,0,1,0,0,0,0,1,1],
        [12,0,2,0,3,0,1,0,0,0,0,1,1],
        [13,0,2,3,0,0,2,0,2,1,0,2,2],
        [14,0,2,4,0,0,2,0,2,1,0,2,2],
        [15,0,2,0,0,1,0,0,0,0,0,0,0],
        [16,0,2,2,0,0,0,0,0,0,0,0,0],
        [17,0,2,0,0,1,1,0,0,0,0,0,0],
        [18,0,2,0,1,2,2,0,1,1,0,1,1],
        [19,0,5,0,0,2,6,2,2,1,0,5,5]]
    for actual in helpers['compile_and_run'](source,tmp_path):assert actual==expected


@pytest.mark.parametrize('signed',[False,True])
def test_debug_adapter_executes_with_all_three_states_without_narrowing_memory(tmp_path,signed):
    import aether_re.pdb_dia as dia
    fixture=runpy.run_path(str(Path(__file__).with_name('test_call_effects.py')))
    export=fixture['memory_export'](tmp_path)
    typed=runpy.run_path(str(Path(__file__).with_name('test_pdb_dia_contract.py')))['typed_payload']()
    typed['types'][1]['base_type']=6 if signed else 7
    typed.update(binary_sha256=export.target_sha256,pdb_sha256='c'*64,helper_sha256='d'*64,dia_dll_sha256='e'*64)
    typed['binding']=dict(status='verified',target_identity_bound=True,target_types_bound=True,
        binary_sha256=export.target_sha256,guid=typed['guid'],age=typed['age'])
    typed['validated_payload_sha256']=dia._payload_digest(typed);typed['validated_report_sha256']=dia._report_digest(typed)
    report=export.select_reconstruction('caller',debug_report=typed,memory_model='bounded-bytes.v2',call_model=fixture['MODEL'])
    adapter=report['debug_return_adapter'];assert adapter['contract']['signed'] is signed
    source=adapter['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned i,j;const unsigned long long pairs[4][2]={{2ULL,3ULL},{250ULL,7ULL},{4294967295ULL,3ULL},{124ULL,4ULL}};
 for(i=0U;i<4U;++i) {
  unsigned char bytes[4],permissions[4]={3U,3U,3U,3U},initialized[4]={1U,1U,1U,1U};
  struct aether_sparse_region region={bytes,permissions,initialized,4096ULL,4ULL};
  struct aether_sparse_memory m={0};struct aether_sparse_event me[4]={{0}};
  struct aether_call_trace c={0};struct aether_call_event ce[4]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[16]={{0}};
  unsigned long long value,stored=0ULL;
  for(j=0U;j<4U;++j)bytes[j]=(unsigned char)(pairs[i][0]>>(j*8U));
  m.regions=&region;m.region_count=1ULL;m.steps_left=100ULL;m.events=me;m.event_capacity=4ULL;
  c.events=ce;c.event_capacity=4ULL;c.depth_limit=4ULL;c.call_limit=10ULL;e.events=ee;e.event_capacity=16ULL;
  value=aether_debug_return(&m,&c,&e,4096ULL,pairs[i][1]);
  for(j=0U;j<4U;++j)stored|=(unsigned long long)bytes[j]<<(j*8U);
  printf("%u %llu %llu %u %u %u %llu %llu %llu %llu %llu %llu\n",i,value,stored,m.status,c.status,e.status,m.steps_executed,m.event_count,c.event_count,e.event_count,c.depth,ce[1].value);
 }
 return 0;
}
'''
    expected=[]
    for index,(initial,delta) in enumerate([(2,3),(250,7),(0xffffffff,3),(124,4)]):
        stored=(initial+delta)&0xffffffff;value=stored&255
        if signed and value>=128:value=(value-256)&0xffffffffffffffff
        expected.append([index,value,stored,0,0,0,6,2,2,6,0,stored])
    for actual in helpers['compile_and_run'](source,tmp_path):assert actual==expected
