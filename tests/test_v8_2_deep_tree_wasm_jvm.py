"""Empirical tests for AetherRE Megazord v8.2.0 Deep Extraction & Structured Bytecode Reconstruction:
1. Pure-Python SquashFS v4 full directory + file tree extraction (compressed zlib blocks -> byte-exact SHA-256).
2. JVM .jar -> structured CFG + locals + loop/if + invokestatic decompilation -> javac -> live java parity + OmniClone JAR route.
3. WASM Global + Data Segment + nested block/loop br/br_if + i32.load8_u + local.tee -> C99 -> MSVC DLL -> ctypes live parity.
"""

from __future__ import annotations

import ctypes
import hashlib
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

from aether_re.omniclone import clone_and_audit_project
from aether_re.project_reconstructor import reconstruct_project
from aether_re.runtime_emitter import compile_reconstructed_project


def _pack_meta_block(payload: bytes, *, compress: bool = True) -> bytes:
    if compress:
        comp = zlib.compress(payload)
        return struct.pack("<H", len(comp)) + comp
    return struct.pack("<H", 0x8000 | len(payload)) + payload


def _build_squashfs_v4_image(files: dict[str, dict[str, bytes]]) -> bytes:
    """Builds a specification-accurate little-endian SquashFS v4 image (root -> subdirs -> zlib files)."""
    block_size = 4096
    data_chunks = bytearray()
    inode_chunks = bytearray()
    dir_chunks = bytearray()

    inode_num_seq = 1
    file_data_start_rel = 96  # Right after 96-byte superblock

    # 2. Build directory table blocks & directory inodes (pack file inodes of each dir into one metadata block!)
    inode_chunks = bytearray()
    inode_num_seq = 1
    root_entries: list[tuple[str, int, int]] = []
    # Re-pack inodes cleanly per directory so offsets match standard SquashFS metadata blocks
    file_inode_map: dict[str, list[tuple[str, int, int, bytes]]] = {}
    for dname, fdict in files.items():
        d_blk_start_in_tbl = len(inode_chunks)
        dir_inodes_blob = bytearray()
        d_files_meta: list[tuple[str, int, int]] = []
        for fname, content in fdict.items():
            f_start_rel = file_data_start_rel + len(data_chunks)
            comp_blk = zlib.compress(content)
            data_chunks.extend(comp_blk)
            ino_num = inode_num_seq
            inode_num_seq += 1
            ino_inner_off = len(dir_inodes_blob)
            ino_bytes = struct.pack(
                "<HHIHHIIIII",
                2, 0o644, 0, 0, 0, ino_num,
                f_start_rel, 0xFFFFFFFF, 0, len(content),
            ) + struct.pack("<I", len(comp_blk))
            dir_inodes_blob.extend(ino_bytes)
            d_files_meta.append((fname, ino_inner_off, ino_num))
        inode_chunks.extend(_pack_meta_block(bytes(dir_inodes_blob)))

        d_blk_rel = len(dir_chunks)
        d_buf = bytearray(struct.pack("<III", len(d_files_meta) - 1, d_blk_start_in_tbl, 1))
        for fname, f_inner_off, _f_ino in d_files_meta:
            nb = fname.encode("utf-8")
            d_buf.extend(struct.pack("<HhHH", f_inner_off, 1, 2, len(nb) - 1) + nb)
        dir_chunks.extend(_pack_meta_block(bytes(d_buf)))

        d_ino_ref = (len(inode_chunks) << 16) | 0
        d_ino_num = inode_num_seq
        inode_num_seq += 1
        d_ino_bytes = struct.pack(
            "<HHIHHIIIHHI",
            1, 0o755, 0, 0, 0, d_ino_num,
            d_blk_rel, len(d_files_meta) + 2, len(d_buf) + 3, 0, 1,
        )
        inode_chunks.extend(_pack_meta_block(d_ino_bytes))
        root_entries.append((dname, d_ino_ref, d_ino_num))

    # 3. Build root directory entry (1 Directory Header per subdir metadata block!) + root inode
    root_dir_blk_rel = len(dir_chunks)
    r_buf = bytearray()
    for dname, d_ref, d_ino in root_entries:
        nb = dname.encode("utf-8")
        r_buf.extend(struct.pack("<III", 0, d_ref >> 16, d_ino))
        r_buf.extend(struct.pack("<HhHH", d_ref & 0xFFFF, 0, 1, len(nb) - 1) + nb)
    dir_chunks.extend(_pack_meta_block(bytes(r_buf)))

    root_inode_ref = (len(inode_chunks) << 16) | 0
    root_ino_num = inode_num_seq
    inode_num_seq += 1
    root_ino = struct.pack(
        "<HHIHHIIIHHI",
        1, 0o755, 0, 0, 0, root_ino_num,
        root_dir_blk_rel, len(root_entries) + 2, len(r_buf) + 3, 0, root_ino_num,
    )
    inode_chunks.extend(_pack_meta_block(root_ino))

    inode_tbl_rel = 96 + len(data_chunks)
    dir_tbl_rel = inode_tbl_rel + len(inode_chunks)
    total_used = dir_tbl_rel + len(dir_chunks)

    sb = struct.pack(
        "<IIIIIHHHHHHQQQQQQQQ",
        0x73717368, inode_num_seq - 1, 0, block_size, 0, 1, 12, 0, 1, 4, 0,
        root_inode_ref, total_used, total_used, 0xFFFFFFFFFFFFFFFF,
        inode_tbl_rel, dir_tbl_rel, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    )
    return sb + bytes(data_chunks) + bytes(inode_chunks) + bytes(dir_chunks)


def test_v82_squashfs_v4_full_tree_byte_exact_extraction(tmp_path: Path) -> None:
    conf_bytes = b'{"service":"aether_fw","port":8443,"strict":true}\n'
    py_bytes = b"def boot():\n    return 'AETHER_OK_82'\n"
    sq_blob = _build_squashfs_v4_image({
        "etc": {"app.conf": conf_bytes},
        "bin": {"run.py": py_bytes},
    })
    # Prepend simulated bootloader padding + ARM MMIO pointer hint before SquashFS superblock
    fw_path = tmp_path / "router_v82.img"
    fw_path.write_bytes(b"\x00\x20\x00\x40" * 4 + sq_blob)

    out_dir = tmp_path / "fw_out"
    rep = reconstruct_project(fw_path, out_dir)
    assert rep.status == "complete"
    assert rep.project_kind == "firmware_rehosted_project"

    ext_conf = out_dir / "rootfs" / "etc" / "app.conf"
    ext_py = out_dir / "rootfs" / "bin" / "run.py"
    assert ext_conf.is_file()
    assert ext_py.is_file()
    assert hashlib.sha256(ext_conf.read_bytes()).hexdigest() == hashlib.sha256(conf_bytes).hexdigest()
    assert hashlib.sha256(ext_py.read_bytes()).hexdigest() == hashlib.sha256(py_bytes).hexdigest()


def test_v82_jvm_jar_branches_loops_and_invokestatic_roundtrip(tmp_path: Path) -> None:
    javac = shutil.which("javac")
    java = shutil.which("java")
    assert javac and java, "JDK javac/java required for live JVM roundtrip verification"

    src_dir = tmp_path / "orig_src" / "demo"
    cls_dir = tmp_path / "orig_cls"
    src_dir.mkdir(parents=True, exist_ok=True)
    cls_dir.mkdir(parents=True, exist_ok=True)

    (src_dir / "LoopCalc.java").write_text(
        "\n".join([
            "package demo;",
            "public class LoopCalc {",
            "    public static int stepMul(int x, int y) {",
            "        return (x * y) + 1;",
            "    }",
            "    public static int sumFiltered(int n, int threshold) {",
            "        int acc = 0;",
            "        for (int i = 0; i < n; i++) {",
            "            if (i > threshold) {",
            "                acc += stepMul(i, 3);",
            "            } else {",
            "                acc += i;",
            "            }",
            "        }",
            "        return acc;",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    subprocess.run([javac, str(src_dir / "LoopCalc.java"), "-d", str(cls_dir)], check=True, timeout=60)
    jar_path = tmp_path / "loop_calc.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.write(cls_dir / "demo" / "LoopCalc.class", "demo/LoopCalc.class")
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

    clone_dir = tmp_path / "omniclone_jar"
    man = clone_and_audit_project(jar_path, clone_dir, run_symbolic=False, run_exploit_audit=False)
    assert man["status"] == "complete"
    assert man["components"][0]["project_kind"] == "android_dex_java"

    lifted_java = clone_dir / "primary_project" / "app" / "src" / "main" / "java" / "demo" / "LoopCalc.java"
    assert lifted_java.is_file()

    rec_cls = tmp_path / "rec_cls"
    rec_cls.mkdir(parents=True, exist_ok=True)
    runner = tmp_path / "Runner.java"
    runner.write_text(
        'public class Runner { public static void main(String[] a) { System.out.println(demo.LoopCalc.sumFiltered(6, 2) + "," + demo.LoopCalc.sumFiltered(4, 10)); } }\n',
        encoding="utf-8",
    )
    subprocess.run([javac, str(lifted_java), str(runner), "-d", str(rec_cls)], check=True, timeout=60)
    run_out = subprocess.check_output([java, "-cp", str(rec_cls), "Runner"], text=True, timeout=30).strip()
    # sumFiltered(6, 2): i=0..2 -> 0+1+2=3; i=3..5 -> (10)+(13)+(16)=39; total=42; sumFiltered(4, 10) = 0+1+2+3=6
    assert run_out == "42,6"


def _uleb(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _wasm_sec(sec_id: int, payload: bytes) -> bytes:
    return bytes([sec_id]) + _uleb(len(payload)) + payload


def test_v82_wasm_globals_data_segment_and_nested_block_loop_br_if_exec(tmp_path: Path) -> None:
    # Type 0: (i32) -> i32
    t_sec = _wasm_sec(1, _uleb(1) + b"\x60\x01\x7f\x01\x7f")
    # Func 0 -> Type 0
    f_sec = _wasm_sec(3, _uleb(1) + _uleb(0))
    # Memory min 1 page
    m_sec = _wasm_sec(5, _uleb(1) + b"\x00\x01")
    # Global 0: i32 const = 10
    g_sec = _wasm_sec(6, _uleb(1) + b"\x7f\x00\x41\x0a\x0b")
    # Export "scan_sum" -> func 0
    nm = b"scan_sum"
    e_sec = _wasm_sec(7, _uleb(1) + _uleb(len(nm)) + nm + b"\x00\x00")
    # Code body: locals (2 i32: l1=sum, l2=i); block { loop { i >= n -> br_if 1; sum += wasm_mem[0x100 + i] + g0; i = tee(i+1); br 0 } }; return sum
    # NOTE: 0x01\x02\x7f = 1 local decl group of 2 i32s
    fn_code = bytes([
        0x01, 0x02, 0x7F,  # locals l1=0, l2=0
        0x02, 0x40,        # block void
        0x03, 0x40,        # loop void
        0x20, 0x02,        # local.get l2 (i)
        0x20, 0x00,        # local.get l0 (n)
        0x4E,              # i32.ge_s
        0x0D, 0x01,        # br_if 1 (break outer block)
        0x20, 0x01,        # local.get l1 (sum)
        0x20, 0x02,        # local.get l2 (i)
        0x2D, 0x00, 0x80, 0x02,  # i32.load8_u offset=0x100 (ULEB128 0x100 = 0x80 0x02)
        0x23, 0x00,        # global.get 0 (10)
        0x6A,              # i32.add
        0x6A,              # i32.add
        0x21, 0x01,        # local.set l1
        0x20, 0x02,        # local.get l2
        0x41, 0x01,        # i32.const 1
        0x6A,              # i32.add
        0x22, 0x02,        # local.tee l2
        0x1A,              # drop
        0x0C, 0x00,        # br 0 (continue loop)
        0x0B,              # end loop
        0x0B,              # end block
        0x20, 0x01,        # local.get l1
        0x0B,              # end func
    ])
    c_sec = _wasm_sec(10, _uleb(1) + _uleb(len(fn_code)) + fn_code)
    # Data segment 0: active at i32.const 0x100 -> bytes [2, 5, 7, 9]
    seg_data = bytes([2, 5, 7, 9])
    d_sec = _wasm_sec(11, _uleb(1) + b"\x00\x41\x80\x02\x0b" + _uleb(len(seg_data)) + seg_data)

    wasm_path = tmp_path / "scan_loop.wasm"
    wasm_path.write_bytes(b"\x00asm\x01\x00\x00\x00" + t_sec + f_sec + m_sec + g_sec + e_sec + c_sec + d_sec)

    out_dir = tmp_path / "wasm_out"
    rep = reconstruct_project(wasm_path, out_dir)
    assert rep.status == "complete"
    assert rep.project_kind == "wasm_native_c"

    bld = compile_reconstructed_project(out_dir, "wasm_v82.dll", source_rel="src/wasm_module.c")
    assert bld["compiled"] is True, bld
    dll = ctypes.CDLL(str(bld["dll_path"]))
    dll.scan_sum.argtypes = [ctypes.c_int64]
    dll.scan_sum.restype = ctypes.c_int64
    assert dll.scan_sum(0) == 0
    assert dll.scan_sum(2) == 27   # (2+10) + (5+10)
    assert dll.scan_sum(4) == 63   # (2+10) + (5+10) + (7+10) + (9+10)
