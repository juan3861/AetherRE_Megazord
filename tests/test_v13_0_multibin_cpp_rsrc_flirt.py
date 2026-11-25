from __future__ import annotations

import io
from pathlib import Path
import struct
import subprocess
import tarfile
import zipfile

import pefile

from aether_re.behavioral_flirt import identify_library_functions_behavioral
from aether_re.cpp_class_reconstructor import reconstruct_cpp_class_hierarchy
from aether_re.omniclone import clone_and_audit_project
from aether_re.project_reconstructor import reconstruct_project
from aether_re.runtime_emitter import _find_msvc_x64_toolchain, compile_reconstructed_executable
from aether_re.unpackers import detect_container_format, unpack_container


def test_v130_cpp_class_reconstructor_multiple_inheritance_and_winrt(tmp_path: Path) -> None:
    cpp_src = tmp_path / "hier.cpp"
    cpp_src.write_text(
        """
        #include <stdint.h>
        struct BaseA {
            int64_t a = 10;
            virtual ~BaseA() = default;
            virtual int64_t getA(int64_t x, int64_t y) { return a + x + y; }
        };
        struct BaseB {
            int64_t b = 20;
            virtual ~BaseB() = default;
            virtual int64_t getB(int64_t x, int64_t y) { return b + x * y; }
        };
        struct DerivedAB : public BaseA, public BaseB {
            int64_t getA(int64_t x, int64_t y) override { return a + x + y + 1; }
            int64_t getB(int64_t x, int64_t y) override { return b + x * y + 2; }
        };
        extern "C" __declspec(dllexport) BaseA* make_a(int k) {
            return k ? static_cast<BaseA*>(new DerivedAB()) : new BaseA();
        }
        extern "C" __declspec(dllexport) BaseB* make_b(int k) {
            return k ? static_cast<BaseB*>(new DerivedAB()) : new BaseB();
        }
        extern "C" __declspec(dllexport) int64_t run_poly(BaseA* pa, BaseB* pb, int64_t x, int64_t y) {
            return pa->getA(x, y) + pb->getB(x, y);
        }
        """,
        encoding="utf-8",
    )
    dll_path = tmp_path / "hier.dll"
    vc_info = _find_msvc_x64_toolchain()
    assert vc_info is not None
    _, env, cl_exe, _ = vc_info
    proc = subprocess.run(
        [cl_exe, "/nologo", "/LD", "/O2", "/EHsc", "/GR", str(cpp_src), f"/Fe:{dll_path}"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.returncode == 0 and dll_path.is_file()

    rep = reconstruct_cpp_class_hierarchy(dll_path.read_bytes(), output_dir=tmp_path / "out_cls")
    assert rep["abi"] == "msvc"
    assert rep["class_count"] >= 3
    names = {c["cpp_name"] for c in rep["classes"]}
    assert {"BaseA", "BaseB", "DerivedAB"}.issubset(names)
    hpp = Path(rep["hpp_path"]).read_text(encoding="utf-8")
    assert "class DerivedAB : public BaseA, public BaseB" in hpp or "class DerivedAB" in hpp

    # Verify WinRT .winmd namespace metadata parsing
    winmd_blob = b"BSJB\x01\x00\x01\x00\x00\x00\x00\x00\x0c\x00\x00\x00v4.0.30319\x00\x00" + b"Windows.Storage.StorageFile\x00Windows.Foundation.Uri\x00"
    winrt_rep = reconstruct_cpp_class_hierarchy(winmd_blob)
    assert winrt_rep["winrt_types_count"] >= 2


def test_v130_behavioral_flirt_identifies_fnv1a_and_crc32_in_x64(tmp_path: Path) -> None:
    c_src = tmp_path / "hashes.c"
    c_src.write_text(
        """
        #include <stdint.h>
        __declspec(dllexport) uint32_t fnv1a_32(const uint8_t* p, uint64_t n) {
            uint32_t h = 2166136261u;
            for (uint64_t i = 0; i < n; ++i) {
                h ^= p[i];
                h *= 16777619u;
            }
            return h;
        }
        __declspec(dllexport) uint32_t crc32_ieee(const uint8_t* p, uint64_t n) {
            uint32_t crc = 0xFFFFFFFFu;
            for (uint64_t i = 0; i < n; ++i) {
                crc ^= p[i];
                for (int b = 0; b < 8; ++b) {
                    crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320u : 0u);
                }
            }
            return crc ^ 0xFFFFFFFFu;
        }
        """,
        encoding="utf-8",
    )
    dll_path = tmp_path / "hashes.dll"
    _, env, cl_exe, _ = _find_msvc_x64_toolchain()
    subprocess.run(
        [cl_exe, "/nologo", "/LD", "/O2", str(c_src), f"/Fe:{dll_path}"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        check=True,
    )
    raw = dll_path.read_bytes()
    pe = pefile.PE(data=raw)
    slices = []
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        off = pe.get_offset_from_rva(sym.address)
        slices.append({"rva": sym.address, "code": raw[off : off + 256]})

    rep = identify_library_functions_behavioral(raw, function_slices=slices)
    found_fns = {m["function"] for m in rep["oss_clusters"]}
    assert "fnv1a_32" in found_fns
    assert "crc32_ieee" in found_fns
    assert "ZLIB::ZLIB" in rep["cmake_find_packages"]


def test_v130_unpackers_deb_rpm_msi_and_multibin_closure_with_rsrc(tmp_path: Path) -> None:
    # 1. Pure-Python .deb ar archive
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        data = b"hello_deb\n"
        ti = tarfile.TarInfo("usr/bin/hello.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tb = tar_buf.getvalue()
    deb_path = tmp_path / "pkg.deb"
    ar_hdr = f"{'data.tar.gz':<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(tb):<10}`\n".encode("ascii")
    deb_path.write_bytes(b"!<arch>\n" + ar_hdr + tb + (b"\n" if len(tb) & 1 else b""))
    assert detect_container_format(deb_path) == "deb"
    deb_out = unpack_container(deb_path, tmp_path / "deb_out")
    assert deb_out["status"] == "unpacked" and (tmp_path / "deb_out" / "data.tar.gz").is_file()

    # 2. RPM & OLE2 MSI carving
    rpm_path = tmp_path / "pkg.rpm"
    rpm_path.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 92 + tb)
    assert detect_container_format(rpm_path) == "rpm"
    rpm_out = unpack_container(rpm_path, tmp_path / "rpm_out")
    assert rpm_out["file_count"] == 1

    msi_path = tmp_path / "setup.msi"
    msi_path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 40 + b"MSCF\x00\x00\x00\x00" + struct.pack("<I", 40) + b"A" * 28)
    assert detect_container_format(msi_path) == "msi_ole2"
    msi_out = unpack_container(msi_path, tmp_path / "msi_out")
    assert msi_out["file_count"] == 1

    # 3. Real multi-binary MSVC app.exe -> helper_lib.dll + embedded rc.exe resource inside ZIP bundle
    _, env, cl_exe, _ = _find_msvc_x64_toolchain()
    dll_c = tmp_path / "helper_lib.c"
    dll_c.write_text('__declspec(dllexport) int helper_calc(int a, int b) { return a * 10 + b; }\n', encoding="utf-8")
    dll_bin = tmp_path / "helper_lib.dll"
    subprocess.run([cl_exe, "/nologo", "/LD", "/O2", str(dll_c), f"/Fe:{dll_bin}"], cwd=str(tmp_path), env=env, check=True, capture_output=True)

    exe_c = tmp_path / "main_app.c"
    exe_c.write_text('__declspec(dllimport) int helper_calc(int a, int b);\nint main(void) { return helper_calc(4, 2); }\n', encoding="utf-8")
    rc_src = tmp_path / "app.rc"
    rc_src.write_text('1 24 "app.manifest"\n', encoding="utf-8")
    (tmp_path / "app.manifest").write_text('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity version="1.0.0.0" name="Aether.TestApp" type="win32"/></assembly>\n', encoding="utf-8")

    # Verify project reconstructor + rc.exe resource embedding on EXE
    rc_exe = subprocess.run(["where", "rc"], env=env, capture_output=True, text=True).stdout.splitlines()[0].strip()
    res_obj = tmp_path / "app.res"
    subprocess.run([rc_exe, "/nologo", "/fo", str(res_obj), str(rc_src)], cwd=str(tmp_path), env=env, check=True, capture_output=True)

    exe_bin = tmp_path / "main_app.exe"
    subprocess.run([cl_exe, "/nologo", "/O2", str(exe_c), str(tmp_path / "helper_lib.lib"), str(res_obj), f"/Fe:{exe_bin}"], cwd=str(tmp_path), env=env, check=True, capture_output=True)

    recon_exe = tmp_path / "recon_main_exe"
    reconstruct_project(exe_bin, recon_exe, max_internal_subroutines=8)
    comp = compile_reconstructed_executable(recon_exe)
    assert comp["compiled"] is True
    assert comp["resources_embedded"] is True

    # OmniClone multi-binary dependency closure on bundle ZIP
    bundle_zip = tmp_path / "app_bundle.zip"
    with zipfile.ZipFile(bundle_zip, "w") as zf:
        zf.write(exe_bin, "bin/main_app.exe")
        zf.write(dll_bin, "bin/helper_lib.dll")

    omni_out = tmp_path / "omni_multibin"
    manifest = clone_and_audit_project(bundle_zip, omni_out, run_symbolic=False, run_exploit_audit=False)
    assert manifest["components_count"] >= 2
    assert "main_app.exe" in manifest["dependency_graph"]
    assert "helper_lib.dll" in manifest["dependency_graph"]["main_app.exe"]
    cmake_ws = (omni_out / "workspace_cmake" / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "add_executable(main_app" in cmake_ws
    assert "add_library(helper_lib SHARED" in cmake_ws
    assert "target_link_libraries(main_app PRIVATE helper_lib)" in cmake_ws
