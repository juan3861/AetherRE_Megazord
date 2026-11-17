"""Legacy timeout/resource cleanup must never wait without a deadline."""
import subprocess
import pytest
import aether_re.process as module

@pytest.mark.parametrize('reason',['timeout','rss','cpu'])
def test_legacy_cleanup_limits_taskkill_and_pipe_drain(monkeypatch,reason):
    class Process:
        pid=123456;returncode=None
        def communicate(self,timeout=None):
            assert timeout is not None,'unbounded pipe drain'
            raise subprocess.TimeoutExpired(['owned'],timeout,output=b'partial\n',stderr=b'')
        def poll(self):return self.returncode
        def kill(self):self.returncode=1
    proc=Process();calls=[]
    monkeypatch.setattr(module.subprocess,'Popen',lambda *a,**k:proc)
    def taskkill(*a,**k):
        assert k.get('timeout') is not None,'unbounded taskkill'
        calls.append(k['timeout']);raise subprocess.TimeoutExpired(['taskkill'],k['timeout'])
    monkeypatch.setattr(module.subprocess,'run',taskkill)
    monkeypatch.setattr(module,'_rss_tree_mb',lambda pid:100)
    monkeypatch.setattr(module,'_cpu_tree_seconds',lambda pid:100)
    ticks=iter([0,1,2,3,4,5,6,7,8,9]);monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    options={'memory_limit_mb':1} if reason=='rss' else {'cpu_time_limit_s':1} if reason=='cpu' else {}
    result=module.run_bounded(['owned'],timeout=.1,**options)
    assert proc.returncode==1
    assert result['capture_complete'] is False
    assert result['stdout']=='partial\n'
    assert result['timed_out']==(reason=='timeout')
    if reason!='timeout':assert result['resource_kind']==reason
    assert calls
