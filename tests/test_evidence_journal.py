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