"""Native checks for lifetime reuse and phi-edge state under trace exhaustion."""
from pathlib import Path
import runpy
from aether_re.call_closure import reconstruct_direct_call_closure

f=runpy.run_path(str(Path(__file__).with_name('test_stack_liveness.py')))
native=runpy.run_path(str(Path(__file__).with_name('test_call_closure_runtime.py')))


def phi_trace_oracle(x,capacity):
    steps=events=calls=starts=0;cstatus=0;acc=5;n=x&3
    def tick():
        nonlocal steps,starts
        steps+=1
        if starts>=capacity:raise StopIteration
        starts+=1
    try:
        tick();tick();tick()
        for index in range(n+1):
            for _ in range(4):tick()
            if index==n:break
            tick();calls+=1;events+=1
            try:tick();acc+=index;tick()
            except StopIteration:cstatus=1;raise
            events+=1;tick();tick()
        tick()
        return [x,capacity,acc,0,0,0,steps,events,calls,0,starts,starts]
    except StopIteration:
        return [x,capacity,0,0,cstatus,2,steps,events,calls,0,starts,starts]


def test_reused_initializer_and_phi_value_keep_a_single_bounded_history(tmp_path):
    report=reconstruct_direct_call_closure(f['phi_reuse_export'](tmp_path),'caller',call_model=f['MODEL'])
    assert report['status']=='complete',report
    assert any('stack_reuse_proof' in i for i in report['call_model']['functions'])
    source=report['structured_c_source']+r'''
#include <stdio.h>
int main(void) {
 unsigned x,capacity;
 for(x=0U;x<8U;++x)for(capacity=0U;capacity<=40U;++capacity) {
  struct aether_sparse_memory m={0};struct aether_call_trace c={0};struct aether_call_event ce[64]={{0}};
  struct aether_effect_trace e={0};struct aether_effect_event ee[64]={{0}};
  unsigned long long result;
  m.steps_left=1000ULL;c.events=ce;c.event_capacity=64ULL;c.depth_limit=4ULL;c.call_limit=10ULL;
  e.events=ee;e.event_capacity=capacity;
  result=aether_recovered(&m,&c,&e,x,5ULL);
  printf("%u %u %llu %u %u %u %llu %llu %llu %llu %llu %llu\n",x,capacity,result,m.status,c.status,e.status,m.steps_executed,c.event_count,c.calls,c.depth,e.event_count,e.last_step);
 }
 return 0;
}
'''
    expected=[phi_trace_oracle(x,capacity) for x in range(8) for capacity in range(41)]
    for actual in native['compile_and_run'](source,tmp_path):assert actual==expected
