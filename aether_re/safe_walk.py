"""Deterministic, pruned source walk; never descends into links or exclusions."""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

COMMON_GENERATED_DIRS = frozenset({"node_modules", ".pytest_cache", ".mypy_cache", ".ruff_cache", "browser_profiles", ".audit-tools-venv", ".build_tmp", ".f55_tmp", "site-packages"})
COMMON_GENERATED_PREFIXES = ("_vendored_", ".clean_gate_venv", "runtimecopy-")
COMMON_GENERATED_SUFFIXES = ("_venv", "_profile")

def should_exclude_dir(name: str, excluded_dirs: set[str] | frozenset[str]) -> bool:
    lower=name.lower(); return lower in COMMON_GENERATED_DIRS or lower in excluded_dirs or lower.startswith(COMMON_GENERATED_PREFIXES) or lower.endswith(COMMON_GENERATED_SUFFIXES)

def iter_files_pruned(root: Path, excluded_dirs: set[str] | frozenset[str]) -> Iterator[Path]:
    excluded={name.lower() for name in excluded_dirs}
    for current, dirs, files in os.walk(root,topdown=True,followlinks=False):
        parent=Path(current)
        dirs[:]=[name for name in sorted(dirs) if not should_exclude_dir(name,excluded) and not (parent/name).is_symlink() and not (hasattr(parent/name,"is_junction") and (parent/name).is_junction())]
        for name in sorted(files): yield parent/name

@dataclass(frozen=True)
class WalkEntry:
    path: Path
    relative_path: str
    kind: str

def _is_link_or_reparse(path: Path, st: os.stat_result) -> bool:
    return path.is_symlink() or bool(getattr(st,"st_file_attributes",0) & getattr(stat,"FILE_ATTRIBUTE_REPARSE_POINT",0)) or (hasattr(path,"is_junction") and path.is_junction())

def inventory_tree_bounded(root: Path, *, max_files: int, max_total_bytes: int, max_file_bytes: int, max_path_length: int) -> list[WalkEntry]:
    root=Path(root)
    try:
        root_stat=root.lstat()
    except OSError as exc: raise ValueError("intake_source_invalid") from exc
    if _is_link_or_reparse(root,root_stat) or not stat.S_ISDIR(root_stat.st_mode): raise ValueError("intake_link_forbidden")
    entries=[]; total=0
    def walk(directory: Path) -> None:
        nonlocal total
        try: children=sorted(list(os.scandir(directory)),key=lambda item:item.name.casefold())
        except OSError as exc: raise ValueError("intake_source_invalid") from exc
        for item in children:
            path=Path(item.path); st=item.stat(follow_symlinks=False)
            if _is_link_or_reparse(path,st): raise ValueError("intake_link_forbidden")
            if stat.S_ISDIR(st.st_mode): walk(path); continue
            if not stat.S_ISREG(st.st_mode): raise ValueError("intake_special_file_forbidden")
            relative=path.relative_to(root).as_posix()
            if len(relative)>max_path_length or st.st_size>max_file_bytes: raise ValueError("intake_file_budget_exceeded")
            total += st.st_size
            entries.append(WalkEntry(path,relative,"file"))
            if len(entries)>max_files or total>max_total_bytes: raise ValueError("intake_total_budget_exceeded")
    walk(root)
    return sorted(entries,key=lambda item:item.relative_path)