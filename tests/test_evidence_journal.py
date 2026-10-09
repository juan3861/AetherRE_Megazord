from pathlib import Path
import hashlib
import stat
from types import SimpleNamespace
import pytest
from aether_re.evidence_journal import EvidenceJournal, JournalCorruption
from aether_re.lock import RunLock
def test_chain_and_tail(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); a=j.append('opened',{'id':'x'}); b=j.append('published',{'id':'y'},parents=(a.entry_hash,)); assert b.sequence==2 and j.verify().status=='pass';
 with j.path.open('ab') as h: h.write(b'{"schema"')
 assert j.recover_interrupted_tail().status=='recovered_tail' and j.verify().status=='pass'
def test_tamper(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'}); j.path.write_text(j.path.read_text().replace('opened','other'))
 with pytest.raises(JournalCorruption): j.verify()

def test_verify_rejects_duplicate_journal_keys_even_when_values_match(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 raw=j.path.read_bytes()
 assert b'"kind":"opened"' in raw
 j.path.write_bytes(raw.replace(b'"kind":"opened"',b'"kind":"opened","kind":"opened"',1))
 with pytest.raises(JournalCorruption,match='journal_json_duplicate_key'): j.verify()

def test_verify_rejects_duplicate_nested_payload_keys(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 raw=j.path.read_bytes()
 assert b'"payload":{"id":"x"}' in raw
 j.path.write_bytes(raw.replace(b'"payload":{"id":"x"}',b'"payload":{"id":"x","id":"x"}',1))
 with pytest.raises(JournalCorruption,match='journal_json_duplicate_key'): j.verify()

def test_verify_rejects_duplicate_head_keys_even_when_values_match(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 raw=j.head_path.read_bytes()
 assert b'"schema":"evidence-journal-head.v1"' in raw
 j.head_path.write_bytes(raw.replace(b'"schema":"evidence-journal-head.v1"',b'"schema":"evidence-journal-head.v1","schema":"evidence-journal-head.v1"',1))
 with pytest.raises(JournalCorruption,match='journal_head_duplicate_key'): j.verify()

def test_verify_rejects_deeply_nested_journal_without_escaping_structured_error(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case')
 nested=b'{"x":'*10000+b'0'+b'}'*10000
 raw=(b'{"schema":"evidence-journal-entry.v1","sequence":1,"kind":"opened",'
      b'"recorded_at":"2026-01-01T00:00:00Z","previous_hash":"'+b'0'*64+
      b'","parents":[],"payload":{"deep":'+nested+b'},"entry_hash":"'+b'0'*64+b'"}\n')
 j.path.write_bytes(raw)
 with pytest.raises(JournalCorruption,match='journal_json_invalid'): j.verify()

def test_verify_rejects_deeply_nested_head_without_escaping_structured_error(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 nested=b'{"x":'*10000+b'0'+b'}'*10000
 j.head_path.write_bytes(b'{"schema":"evidence-journal-head.v1","entries":1,"head_hash":"'+b'0'*64+b'","deep":'+nested+b'}\n')
 with pytest.raises(JournalCorruption,match='journal_head_invalid'): j.verify()

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

def test_recovery_refuses_busy_writer_lock_without_reading_or_mutating_journal(tmp_path: Path, monkeypatch):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 with j.path.open('ab') as handle: handle.write(b'{"partial"')
 original=j.path.read_bytes(); original_head=j.head_path.read_bytes()
 real_read_bytes=Path.read_bytes
 def guarded_read_bytes(path):
  if path == j.path:
   raise AssertionError('journal state read before writer lock acquired')
  return real_read_bytes(path)
 monkeypatch.setattr(Path,'read_bytes',guarded_read_bytes)
 with RunLock(j.case_dir/'journal.writer.lock'):
  with pytest.raises(JournalCorruption,match='journal_writer_locked'):
   j.recover_interrupted_tail()
  assert real_read_bytes(j.path)==original
  assert real_read_bytes(j.head_path)==original_head
  assert not list(j.case_dir.glob('journal.tail.*.quarantine'))

def test_open_rejects_case_directory_symlink(tmp_path: Path):
 real_case=tmp_path/'real-case'; real_case.mkdir()
 alias=tmp_path/'case-alias'
 try: alias.symlink_to(real_case,target_is_directory=True)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'directory symlinks unavailable: {exc}')
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:case_dir:reparse'):
  EvidenceJournal.open(alias)

def test_open_rejects_junction_component(tmp_path: Path, monkeypatch):
 from aether_re import evidence_journal
 case_parent=tmp_path/'case-parent'; case_parent.mkdir()
 monkeypatch.setattr(evidence_journal.os.path,'isjunction',lambda path: Path(path)==case_parent,raising=False)
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:case_dir:reparse'):
  EvidenceJournal.open(case_parent/'case')

def test_open_rejects_windows_reparse_attribute(tmp_path: Path, monkeypatch):
 from aether_re import evidence_journal
 case_parent=tmp_path/'case-parent'; case_parent.mkdir()
 real_lstat=evidence_journal.os.lstat
 def reparse_lstat(path):
  if Path(path)==case_parent:
   return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_file_attributes=0x400,st_nlink=1)
  return real_lstat(path)
 monkeypatch.setattr(evidence_journal.os,'lstat',reparse_lstat)
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:case_dir:reparse'):
  EvidenceJournal.open(case_parent/'case')

def test_verify_rejects_hardlinked_journal(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 alias=tmp_path/'journal-alias.jsonl'
 try: alias.hardlink_to(j.path)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'hardlinks unavailable: {exc}')
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:journal:hardlink'):
  j.verify()

def test_verify_rejects_head_symlink(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 outside=tmp_path/'outside-head.json'; outside.write_bytes(j.head_path.read_bytes())
 j.head_path.unlink()
 try: j.head_path.symlink_to(outside)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'file symlinks unavailable: {exc}')
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:head:reparse'):
  j.verify()

def test_verify_rejects_hardlinked_head(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 alias=tmp_path/'head-alias.json'
 try: alias.hardlink_to(j.head_path)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'hardlinks unavailable: {exc}')
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:head:hardlink'):
  j.verify()

def test_recovery_refuses_symlink_temp_before_quarantining_or_removing_it(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 tail=b'{"partial"'
 with j.path.open('ab') as handle: handle.write(tail)
 digest=hashlib.sha256(tail).hexdigest()
 temporary=j.case_dir/f'.journal.recovery.{digest}.tmp'
 outside=tmp_path/'outside-temp'; outside.write_text('keep',encoding='utf-8')
 try: temporary.symlink_to(outside)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'file symlinks unavailable: {exc}')
 original=j.path.read_bytes()
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:recovery_temp:reparse'):
  j.recover_interrupted_tail()
 assert temporary.is_symlink()
 assert outside.read_text(encoding='utf-8')=='keep'
 assert j.path.read_bytes()==original
 assert not list(j.case_dir.glob('journal.tail.*.quarantine'))

def test_recovery_refuses_hardlinked_temp_before_quarantining(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 tail=b'{"partial"'
 with j.path.open('ab') as handle: handle.write(tail)
 digest=hashlib.sha256(tail).hexdigest()
 temporary=j.case_dir/f'.journal.recovery.{digest}.tmp'
 outside=tmp_path/'outside-temp'; outside.write_text('preserve',encoding='utf-8')
 try: temporary.hardlink_to(outside)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'hardlinks unavailable: {exc}')
 original=j.path.read_bytes()
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:recovery_temp:hardlink'):
  j.recover_interrupted_tail()
 assert temporary.exists() and outside.read_text(encoding='utf-8')=='preserve'
 assert j.path.read_bytes()==original
 assert not list(j.case_dir.glob('journal.tail.*.quarantine'))

def test_append_refuses_symlink_head_temp_before_appending(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('opened',{'id':'x'})
 original_journal=j.path.read_bytes(); original_head=j.head_path.read_bytes()
 temporary=j._head_temp_path
 outside=tmp_path/'outside-head-temp'; outside.write_text('keep',encoding='utf-8')
 try: temporary.symlink_to(outside)
 except (OSError,NotImplementedError) as exc: pytest.skip(f'file symlinks unavailable: {exc}')
 with pytest.raises(JournalCorruption,match='journal_path_unsafe:head_temp:reparse'):
  j.append('published',{'id':'y'})
 assert j.path.read_bytes()==original_journal
 assert j.head_path.read_bytes()==original_head
 assert temporary.is_symlink() and outside.read_text(encoding='utf-8')=='keep'
