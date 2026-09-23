from pathlib import Path
import pytest
from aether_re.evidence_journal import EvidenceJournal, JournalCorruption
def test_chain_and_tail(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); a=j.append('opened',{'id':'x'}); b=j.append('published',{'id':'y'},parents=(a.entry_hash,)); assert b.sequence==2 and j.verify().status=='pass';
 with j.path.open('ab') as h: h.write(b'{"schema"')
 assert j.recover_interrupted_tail().status=='recovered_tail' and j.verify().status=='pass'
def test_tamper(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'}); j.path.write_text(j.path.read_text().replace('opened','other'))
 with pytest.raises(JournalCorruption): j.verify()

def test_recovery_durably_quarantines_before_replacing_live_journal(tmp_path: Path, monkeypatch):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 with j.path.open('ab') as handle: handle.write(b'{"partial"')
 original=j.path.read_bytes(); real_replace=__import__('os').replace
 def fail_journal_replace(source, destination):
  if Path(destination)==j.path: raise OSError('injected_replace_crash')
  return real_replace(source,destination)
 monkeypatch.setattr('aether_re.evidence_journal.os.replace',fail_journal_replace)
 with pytest.raises(OSError,match='injected_replace_crash'): j.recover_interrupted_tail()
 assert j.path.read_bytes()==original
 quarantines=list((tmp_path/'case').glob('journal.tail.*.quarantine'))
 assert len(quarantines)==1 and quarantines[0].read_bytes()==b'{"partial"'
 monkeypatch.setattr('aether_re.evidence_journal.os.replace',real_replace)
 assert j.recover_interrupted_tail().status=='recovered_tail'
 assert j.verify().status=='pass'

def test_recovery_rolls_back_live_journal_when_head_commit_fails(tmp_path: Path, monkeypatch):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 with j.path.open('ab') as handle: handle.write(b'{"partial"')
 original=j.path.read_bytes(); original_head=j.head_path.read_bytes()
 monkeypatch.setattr(j,'_write_head',lambda *_: (_ for _ in ()).throw(OSError('head_commit_failed')))
 with pytest.raises(OSError,match='head_commit_failed'): j.recover_interrupted_tail()
 assert j.path.read_bytes()==original and j.head_path.read_bytes()==original_head
 assert next((tmp_path/'case').glob('journal.tail.*.quarantine')).read_bytes()==b'{"partial"'
