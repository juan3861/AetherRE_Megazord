import zipfile
from pathlib import Path
import pytest
from aether_re.archive_intake import ArchiveRejected, extract_archive_bounded
from aether_re.kernel_contracts import IntakeLimits
def test_traversal_and_ratio(tmp_path: Path):
 z=tmp_path/'x.zip';
 with zipfile.ZipFile(z,'w',compression=zipfile.ZIP_DEFLATED) as a: a.writestr('../x',b'a')
 with pytest.raises(ArchiveRejected,match='archive_path_unsafe'): extract_archive_bounded(z,tmp_path/'stage',limits=IntakeLimits())
 z=tmp_path/'bomb.zip';
 with zipfile.ZipFile(z,'w',compression=zipfile.ZIP_DEFLATED) as a: a.writestr('x',b'0'*100000)
 with pytest.raises(ArchiveRejected,match='archive_compression_ratio_exceeded'): extract_archive_bounded(z,tmp_path/'stage2',limits=IntakeLimits(max_compression_ratio=2))
 assert not (tmp_path/'stage2').exists()