#!/usr/bin/env python3
import argparse
import ctypes
from compression import zstd
from contextlib import ExitStack
from enum import IntEnum
import io
import json
import logging
import mmap
from pathlib import PosixPath as Path
import stat
import sys
import tarfile
from typing import NoReturn, Optional, Type
import zlib

logger = logging.getLogger(__name__)

class FormatError(ValueError):
    pass

def panic(msg: str, etype: Type[Exception] = ValueError) -> NoReturn:
    logger.fatal(msg)
    raise etype(msg)

class AdbCompressionAlg(IntEnum):
    NONE = 0
    DEFLATE = 1
    ZSTD = 2

class AdbSchema(IntEnum):
    PACKAGE = 0x676B6370
    INDEX = 0x78646E69

class AdbBlockType(IntEnum):
    ADB = 0
    SIG = 1
    DATA = 2
    EXT = 3

# C type aliases
Cu8 = ctypes.c_uint8
Cu16 = ctypes.c_uint16
Cu32 = ctypes.c_uint32
Cu64 = ctypes.c_uint64
CAdbSchema = Cu32

class CAdbCompressionSpec(ctypes.LittleEndianStructure):
    _fields_ = (("alg",   Cu8),
                ("level", Cu8))

class CAdbBlock(ctypes.LittleEndianStructure):
    _fields_ = (("type_size", Cu32),
                ("reserved", Cu32),
                ("x_size", Cu64))

class CAdbHdr(ctypes.LittleEndianStructure):
    _fields_ = (("adb_compat_ver", Cu8),
                ("adb_ver", Cu8),
                ("reserved", Cu16),
                ("root", Cu32))

class CAdbSignHdr(ctypes.LittleEndianStructure):
    _fields_ = (("sign_ver", Cu8),
                ("hash_alg", Cu8))

class CAdbDataPackage(ctypes.LittleEndianStructure):
    _fields_ = (("path_idx", Cu32),
                ("file_idx", Cu32))

# Cached size constants for hot-path parsing
SZ_CU32 = ctypes.sizeof(Cu32)
SZ_CADB_SCHEMA = ctypes.sizeof(CAdbSchema)
SZ_CADB_BLOCK = ctypes.sizeof(CAdbBlock)
SZ_CADB_HDR = ctypes.sizeof(CAdbHdr)
SZ_CADB_SIGN_HDR = ctypes.sizeof(CAdbSignHdr)
SZ_CADB_DATA_PACKAGE = ctypes.sizeof(CAdbDataPackage)

class AdbValType(IntEnum):
    SPECIAL = 0x00000000
    INT = 0x10000000
    INT32 = 0x20000000
    INT64 = 0x30000000
    BLOB8 = 0x80000000
    BLOB16 = 0x90000000
    BLOB32 = 0xA0000000
    ARRAY = 0xD0000000
    OBJECT = 0xE0000000

class AdbPkgField(IntEnum):
    PKGINFO = 1
    PATHS = 2

class AdbPkgInfoField(IntEnum):
    HASHES = 3
    DEPENDS = 15
    PROVIDES = 16
    REPLACES = 17
    INSTALL_IF = 18
    RECOMMENDS = 19
    TAGS = 21
    REPO_COMMIT = 10

class AdbDirField(IntEnum):
    NAME = 1
    ACL = 2
    FILES = 3

class AdbFileField(IntEnum):
    NAME = 1
    ACL = 2
    SIZE = 3
    MTIME = 4
    TARGET = 6

class AdbDepField(IntEnum):
    NAME = 1
    VERSION = 2
    MATCH = 3

class AdbAclField(IntEnum):
    MODE = 1
    USER = 2
    GROUP = 3

class ApkVersionFlag(IntEnum):
    EQUAL = 1
    LESS = 2
    GREATER = 4
    FUZZY = 8
    CONFLICT = 16

class AdbReader:
    VAL_TYPE_MASK = 0xF0000000
    VAL_DATA_MASK = 0x0FFFFFFF
    PKGINFO_NAMES = {
        1: "name",
        2: "version",
        3: "hashes",
        4: "description",
        5: "arch",
        6: "license",
        7: "origin",
        8: "maintainer",
        9: "url",
        10: "repo-commit",
        11: "build-time",
        12: "installed-size",
        13: "file-size",
        14: "provider-priority",
        15: "depends",
        16: "provides",
        17: "replaces",
        18: "install-if",
        19: "recommends",
        20: "layer",
        21: "tags",
    }
    PKGINFO_DEP_FIELDS = {
        int(AdbPkgInfoField.DEPENDS),
        int(AdbPkgInfoField.PROVIDES),
        int(AdbPkgInfoField.REPLACES),
        int(AdbPkgInfoField.INSTALL_IF),
        int(AdbPkgInfoField.RECOMMENDS),
    }
    PKGINFO_HEX_FIELDS = {
        int(AdbPkgInfoField.HASHES),
        int(AdbPkgInfoField.REPO_COMMIT),
    }
    DEPMASK_ANY = int(ApkVersionFlag.EQUAL) | int(ApkVersionFlag.LESS) | int(ApkVersionFlag.GREATER)
    DEPMASK_CHECKSUM = int(ApkVersionFlag.LESS) | int(ApkVersionFlag.GREATER)

    def __init__(self, adb_payload: bytes):
        self.adb = adb_payload

    def _val_type(self, v: int) -> int:
        return v & self.VAL_TYPE_MASK

    def _val_data(self, v: int) -> int:
        return v & self.VAL_DATA_MASK

    def _u16(self, off: int) -> int:
        if off + ctypes.sizeof(Cu16) > len(self.adb):
            panic(f"Truncated u16 at offset {off}", FormatError)
        return Cu16.from_buffer_copy(self.adb, off).value

    def _u32(self, off: int) -> int:
        if off + SZ_CU32 > len(self.adb):
            panic(f"Truncated u32 at offset {off}", FormatError)
        return Cu32.from_buffer_copy(self.adb, off).value

    def _u64(self, off: int) -> int:
        if off + ctypes.sizeof(Cu64) > len(self.adb):
            panic(f"Truncated u64 at offset {off}", FormatError)
        return Cu64.from_buffer_copy(self.adb, off).value

    def read_int(self, v: int) -> Optional[int]:
        t = self._val_type(v)
        off = self._val_data(v)
        if t == AdbValType.INT:
            return off
        if t == AdbValType.INT32:
            return self._u32(off)
        if t == AdbValType.INT64:
            return self._u64(off)
        return None

    def read_blob(self, v: int) -> Optional[bytes]:
        t = self._val_type(v)
        off = self._val_data(v)
        if t == AdbValType.SPECIAL and v == 0:
            return None
        if t == AdbValType.BLOB8:
            if off >= len(self.adb):
                panic(f"Truncated blob8 length at offset {off}", FormatError)
            length = self.adb[off]
            start = off + 1
        elif t == AdbValType.BLOB16:
            length = self._u16(off)
            start = off + 2
        elif t == AdbValType.BLOB32:
            length = self._u32(off)
            start = off + 4
        else:
            return None
        end = start + length
        if end > len(self.adb):
            panic(f"Blob at offset {off} exceeds ADB payload", FormatError)
        return bytes(self.adb[start:end])

    def read_obj(self, v: int) -> list[int]:
        t = self._val_type(v)
        if t != AdbValType.ARRAY and t != AdbValType.OBJECT:
            panic(f"Expected object/array value, got type {t:#x}", FormatError)
        off = self._val_data(v)
        num = self._u32(off)
        if num == 0:
            panic(f"Invalid zero-sized object/array at offset {off}", FormatError)
        end = off + num * SZ_CU32
        if end > len(self.adb):
            panic(f"Object/array at offset {off} exceeds ADB payload", FormatError)
        return [Cu32.from_buffer_copy(self.adb, off + i * SZ_CU32).value for i in range(num)]

    @staticmethod
    def obj_get(obj: list[int], index: int | IntEnum) -> int:
        idx = int(index)
        if idx < len(obj):
            return obj[idx]
        return 0

    @staticmethod
    def blob_to_text(blob: Optional[bytes]) -> Optional[str]:
        if blob is None:
            return None
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            return blob.hex()

    def _dep_op_string(self, op: int) -> str:
        base = op & ~int(ApkVersionFlag.CONFLICT)
        op_map = {
            int(ApkVersionFlag.LESS): "<",
            int(ApkVersionFlag.LESS) | int(ApkVersionFlag.EQUAL): "<=",
            int(ApkVersionFlag.LESS) | int(ApkVersionFlag.EQUAL) | int(ApkVersionFlag.FUZZY): "<~",
            int(ApkVersionFlag.EQUAL) | int(ApkVersionFlag.FUZZY): "~",
            int(ApkVersionFlag.FUZZY): "~",
            int(ApkVersionFlag.EQUAL): "=",
            int(ApkVersionFlag.GREATER) | int(ApkVersionFlag.EQUAL): ">=",
            int(ApkVersionFlag.GREATER) | int(ApkVersionFlag.EQUAL) | int(ApkVersionFlag.FUZZY): ">~",
            int(ApkVersionFlag.GREATER): ">",
            self.DEPMASK_CHECKSUM: "><",
            self.DEPMASK_ANY: "",
        }
        return op_map.get(base, "?")

    def parse_dep(self, dep_tag: int) -> Optional[str]:
        dep = self.read_obj(dep_tag)
        name = self.blob_to_text(self.read_blob(self.obj_get(dep, AdbDepField.NAME)))
        ver = self.blob_to_text(self.read_blob(self.obj_get(dep, AdbDepField.VERSION)))
        op = self.read_int(self.obj_get(dep, AdbDepField.MATCH))
        if name is None:
            return None
        if op is None:
            op = int(ApkVersionFlag.EQUAL)
        conflict = "!" if (op & int(ApkVersionFlag.CONFLICT)) else ""
        if ver is None:
            return f"{conflict}{name}"
        return f"{conflict}{name}{self._dep_op_string(op)}{ver}"

    def parse_dep_array(self, arr_tag: int) -> list[str]:
        out = []
        arr = self.read_obj(arr_tag)
        for i in range(1, len(arr)):
            tag = arr[i]
            if tag == 0:
                continue
            dep = self.parse_dep(tag)
            if dep is not None:
                out.append(dep)
        return out

    def parse_string_array(self, arr_tag: int) -> list[str]:
        out = []
        arr = self.read_obj(arr_tag)
        for i in range(1, len(arr)):
            tag = arr[i]
            if tag == 0:
                continue
            text = self.blob_to_text(self.read_blob(tag))
            if text is not None:
                out.append(text)
        return out

    def parse_pkginfo(self, pkginfo_tag: int) -> dict[str, object]:
        meta = {}
        obj = self.read_obj(pkginfo_tag)
        for idx in range(1, len(obj)):
            tag = obj[idx]
            if tag == 0:
                continue
            name = self.PKGINFO_NAMES.get(idx, f"field-{idx}")
            if idx in self.PKGINFO_DEP_FIELDS:
                meta[name] = self.parse_dep_array(tag)
                continue
            if idx == int(AdbPkgInfoField.TAGS):
                meta[name] = self.parse_string_array(tag)
                continue
            ival = self.read_int(tag)
            if ival is not None:
                meta[name] = ival
                continue
            blob = self.read_blob(tag)
            if blob is None:
                continue
            if idx in self.PKGINFO_HEX_FIELDS:
                meta[name] = blob.hex()
            else:
                meta[name] = self.blob_to_text(blob)
        return meta

    def _parse_acl(self, acl_tag: int, default_mode: int) -> tuple[int, Optional[str], Optional[str]]:
        if acl_tag == 0:
            return default_mode, None, None
        acl = self.read_obj(acl_tag)
        mode = self.read_int(self.obj_get(acl, AdbAclField.MODE))
        user = self.blob_to_text(self.read_blob(self.obj_get(acl, AdbAclField.USER)))
        group = self.blob_to_text(self.read_blob(self.obj_get(acl, AdbAclField.GROUP)))
        return (default_mode if mode is None else int(mode)), user, group

    @staticmethod
    def _parse_target_blob(target: Optional[bytes]) -> tuple[str, Optional[str], Optional[int]]:
        if not target:
            return "file", None, None
        if len(target) < 2:
            panic("Invalid target blob too short", FormatError)
        tmode = int.from_bytes(target[0:2], "little")
        payload = target[2:]
        ftype = stat.S_IFMT(tmode)
        if ftype == stat.S_IFLNK:
            try:
                return "symlink", payload.decode("utf-8"), None
            except UnicodeDecodeError:
                return "symlink", payload.decode("utf-8", errors="surrogateescape"), None
        if ftype == stat.S_IFREG:
            try:
                return "hardlink", payload.decode("utf-8"), None
            except UnicodeDecodeError:
                return "hardlink", payload.decode("utf-8", errors="surrogateescape"), None
        if ftype in (stat.S_IFBLK, stat.S_IFCHR, stat.S_IFIFO):
            if len(payload) != 8:
                panic("Invalid device/fifo target blob length", FormatError)
            return "special", None, int.from_bytes(payload, "little")
        return "unknown", None, None

    def parse_package(self) -> tuple[dict[str, object], list[dict[str, object]], list[dict[str, object]], dict[tuple[int, int], dict[str, object]]]:
        if len(self.adb) < SZ_CADB_HDR:
            panic("ADB payload too small for header", FormatError)
        hdr = _read_struct(self.adb, 0, CAdbHdr)
        pkg = self.read_obj(hdr.root)

        metadata = {}
        pkginfo_tag = self.obj_get(pkg, AdbPkgField.PKGINFO)
        if pkginfo_tag != 0:
            metadata = self.parse_pkginfo(pkginfo_tag)

        dirs = []
        file_entries = []
        file_lookup = {}
        paths_tag = self.obj_get(pkg, AdbPkgField.PATHS)
        if paths_tag == 0:
            return metadata, dirs, file_entries, file_lookup

        paths = self.read_obj(paths_tag)
        for path_idx in range(1, len(paths)):
            path_tag = paths[path_idx]
            if path_tag == 0:
                continue
            path = self.read_obj(path_tag)
            path_name = self.blob_to_text(self.read_blob(self.obj_get(path, AdbDirField.NAME))) or ""
            dmode, duser, dgroup = self._parse_acl(self.obj_get(path, AdbDirField.ACL), 0o755)
            dirs.append({
                "path": path_name,
                "mode": dmode,
                "user": duser,
                "group": dgroup,
                "path_idx": path_idx,
            })
            files_tag = self.obj_get(path, AdbDirField.FILES)
            if files_tag == 0:
                continue
            file_arr = self.read_obj(files_tag)
            for file_idx in range(1, len(file_arr)):
                file_tag = file_arr[file_idx]
                if file_tag == 0:
                    continue
                file_obj = self.read_obj(file_tag)
                file_name = self.blob_to_text(self.read_blob(self.obj_get(file_obj, AdbFileField.NAME)))
                if file_name is None:
                    continue
                full = f"{path_name}/{file_name}" if path_name else file_name
                fmode, fuser, fgroup = self._parse_acl(self.obj_get(file_obj, AdbFileField.ACL), 0o644)
                fsize = self.read_int(self.obj_get(file_obj, AdbFileField.SIZE))
                fmtime = self.read_int(self.obj_get(file_obj, AdbFileField.MTIME))
                target_blob = self.read_blob(self.obj_get(file_obj, AdbFileField.TARGET))
                fkind, flink, fdev = self._parse_target_blob(target_blob)
                info = {
                    "path": full,
                    "name": file_name,
                    "path_idx": path_idx,
                    "file_idx": file_idx,
                    "kind": fkind,
                    "size": 0 if fsize is None else int(fsize),
                    "mtime": 0 if fmtime is None else int(fmtime),
                    "mode": fmode,
                    "user": fuser,
                    "group": fgroup,
                    "link_target": flink,
                    "device": fdev,
                }
                file_entries.append(info)
                file_lookup[(path_idx, file_idx)] = info
        return metadata, dirs, file_entries, file_lookup

def _tarinfo_base(name: str, mode: int, mtime: int) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name=name)
    ti.mode = mode & 0o7777
    ti.mtime = int(mtime)
    return ti

def _tar_add_parent_dirs(tar: tarfile.TarFile, path: str, seen_dirs: set[str]):
    parts = Path(path).parts[:-1]
    current = ""
    for part in parts:
        current = f"{current}/{part}" if current else part
        if current in seen_dirs:
            continue
        ti = _tarinfo_base(f"{current}/", 0o755, 0)
        ti.type = tarfile.DIRTYPE
        ti.size = 0
        tar.addfile(ti)
        seen_dirs.add(current)

def _tar_add_dir(tar: tarfile.TarFile, d: dict[str, object], seen_dirs: set[str]):
    path = str(d["path"])
    if not path or path in seen_dirs:
        return
    _tar_add_parent_dirs(tar, path, seen_dirs)
    ti = _tarinfo_base(f"{path}/", int(d["mode"]), 0)
    ti.type = tarfile.DIRTYPE
    ti.size = 0
    tar.addfile(ti)
    seen_dirs.add(path)

def _tar_add_nondata_file(tar: tarfile.TarFile, f: dict[str, object], seen_dirs: set[str]):
    kind = str(f["kind"])
    path = str(f["path"])
    _tar_add_parent_dirs(tar, path, seen_dirs)
    if kind == "file" and int(f["size"]) == 0:
        ti = _tarinfo_base(path, int(f["mode"]), int(f["mtime"]))
        ti.size = 0
        tar.addfile(ti, io.BytesIO())
        return
    if kind == "symlink":
        ti = _tarinfo_base(path, int(f["mode"]), int(f["mtime"]))
        ti.type = tarfile.SYMTYPE
        ti.linkname = str(f["link_target"] or "")
        ti.size = 0
        tar.addfile(ti)
        return
    if kind == "hardlink":
        ti = _tarinfo_base(path, int(f["mode"]), int(f["mtime"]))
        ti.type = tarfile.LNKTYPE
        ti.linkname = str(f["link_target"] or "")
        ti.size = 0
        tar.addfile(ti)

def _tar_add_data_file(tar: tarfile.TarFile, f: dict[str, object], payload: bytes, seen_dirs: set[str]):
    path = str(f["path"])
    _tar_add_parent_dirs(tar, path, seen_dirs)
    ti = _tarinfo_base(path, int(f["mode"]), int(f["mtime"]))
    ti.size = len(payload)
    tar.addfile(ti, io.BytesIO(payload))

def _align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment

def _read_struct(buf, offset: int, struct_type: type[ctypes.Structure]):
    size = ctypes.sizeof(struct_type)
    if offset + size > len(buf):
        panic(f"Truncated {struct_type.__name__} at offset {offset}", FormatError)
    return struct_type.from_buffer_copy(buf, offset)

def _parse_block(buf, offset: int, limit: int) -> tuple[int, int, int, int]:
    if offset + SZ_CU32 > limit:
        panic(f"Truncated block type/size at offset {offset}", FormatError)

    type_size = Cu32.from_buffer_copy(buf, offset).value
    block_type = type_size >> 30
    if block_type == AdbBlockType.EXT:
        blk = _read_struct(buf, offset, CAdbBlock)
        block_type = type_size & 0x3fffffff
        raw_size = blk.x_size
        hdr_size = SZ_CADB_BLOCK
    else:
        raw_size = type_size & 0x3fffffff
        hdr_size = SZ_CU32

    if raw_size < hdr_size:
        panic(f"Invalid block raw size {raw_size} at offset {offset}", FormatError)
    if offset + raw_size > limit:
        panic(f"Block at offset {offset} exceeds stream boundary", FormatError)

    next_offset = offset + _align_up(raw_size, 8)
    if next_offset > limit:
        panic(f"Block padding at offset {offset} exceeds stream boundary", FormatError)

    return block_type, hdr_size, raw_size - hdr_size, next_offset

def _dump_blocks(buf, offset: int, limit: int, schema: int, tar: tarfile.TarFile, meta_schemas: list[dict[str, object]]) -> int:
    seen_adb = False
    seen_data = False
    file_lookup: dict[tuple[int, int], dict[str, object]] = {}
    written_data: set[tuple[int, int]] = set()
    seen_dirs: set[str] = set()
    index = 0

    while offset < limit:
        block_type, hdr_size, payload_size, next_offset = _parse_block(buf, offset, limit)
        payload_off = offset + hdr_size

        match block_type:
            case AdbBlockType.ADB:
                if seen_adb or seen_data:
                    panic("Invalid block order: ADB block after SIG/DATA", FormatError)
                if payload_size < SZ_CADB_HDR:
                    panic("ADB block payload too small", FormatError)
                adb_hdr = _read_struct(buf, payload_off, CAdbHdr)
                logger.info(
                    f"  [{index}] ADB payload={payload_size} compat={adb_hdr.adb_compat_ver} ver={adb_hdr.adb_ver}"
                )
                if schema == AdbSchema.PACKAGE:
                    metadata, dirs, files, file_lookup = AdbReader(
                        bytes(buf[payload_off:payload_off + payload_size])
                    ).parse_package()
                    meta_schemas.append({
                        "schema": "package",
                        "metadata": metadata,
                        "dirs": dirs,
                        "files": files,
                    })
                    if metadata:
                        logger.info("    package metadata:")
                        for key, value in metadata.items():
                            logger.info(f"      {key}: {value}")
                    else:
                        logger.info("    package metadata: (none)")
                    logger.info(f"    all file paths ({len(files)}):")
                    for f in files:
                        logger.info(f"      {f['path']}")

                    for d in dirs:
                        _tar_add_dir(tar, d, seen_dirs)
                    for f in files:
                        _tar_add_nondata_file(tar, f, seen_dirs)
                seen_adb = True
            case AdbBlockType.SIG:
                if not seen_adb or seen_data:
                    panic("Invalid block order: SIG block position", FormatError)
                if payload_size < SZ_CADB_SIGN_HDR:
                    panic("SIG block payload too small", FormatError)
                sig = _read_struct(buf, payload_off, CAdbSignHdr)
                logger.info(
                    f"  [{index}] SIG payload={payload_size} sign_v={sig.sign_ver} hash_alg={sig.hash_alg}"
                )
            case AdbBlockType.DATA:
                if not seen_adb:
                    panic("Invalid block order: DATA before ADB", FormatError)
                seen_data = True
                if schema == AdbSchema.PACKAGE:
                    if payload_size < SZ_CADB_DATA_PACKAGE:
                        panic("Package DATA block payload too small", FormatError)
                    hdr = _read_struct(buf, payload_off, CAdbDataPackage)
                    data_len = payload_size - SZ_CADB_DATA_PACKAGE
                    file_info = file_lookup.get((hdr.path_idx, hdr.file_idx))
                    logger.info(
                        f"  [{index}] DATA path_idx={hdr.path_idx} file_idx={hdr.file_idx} data_len={data_len}"
                    )
                    if file_info is None:
                        panic(f"Unexpected DATA block for path_idx={hdr.path_idx} file_idx={hdr.file_idx}", FormatError)
                    logger.info(f"      path={file_info['path']}")

                    key = (hdr.path_idx, hdr.file_idx)
                    if key in written_data:
                        panic(f"Duplicate DATA block for path_idx={hdr.path_idx} file_idx={hdr.file_idx}", FormatError)
                    written_data.add(key)

                    if str(file_info["kind"]) != "file":
                        panic(f"DATA block points to non-regular file '{file_info['path']}'", FormatError)
                    payload = bytes(buf[payload_off + SZ_CADB_DATA_PACKAGE:payload_off + payload_size])
                    if len(payload) != int(file_info["size"]):
                        panic(
                            f"DATA size mismatch for '{file_info['path']}': {len(payload)} != {file_info['size']}",
                            FormatError,
                        )
                    _tar_add_data_file(tar, file_info, payload, seen_dirs)
                else:
                    logger.info(f"  [{index}] DATA payload={payload_size}")
            case _:
                panic(f"Unknown block type {block_type} at offset {offset}", FormatError)

        offset = next_offset
        index += 1

    if not seen_adb:
        panic("ADB stream did not contain an ADB block", FormatError)
    return offset

def dump(path_apk: Path, path_tar: Optional[Path], path_meta: Optional[Path]):
    with ExitStack() as stack:
        f = stack.enter_context(path_apk.open("rb"))
        size = f.seek(0, io.SEEK_END)
        if size < 4:
            panic("File too small, meanless to dump")
        mm = stack.enter_context(mmap.mmap(f.fileno(), size, access=mmap.ACCESS_READ))
        if mm[0:3] != b"ADB":
            panic("File is not an APK", FormatError)
        match mm[3]:
            case 0x2e: # .: None
                body = mm
                offset = 4
            case 0x64: # d: Deflate
                body = zlib.decompress(mm[4:], wbits=-15)
                if body[0:3] != b"ADB":
                    panic("Inner deflate stream is not an APK", FormatError)
                offset = 4
                stack.close()
                del mm
                del f
            case 0x63: # c: APK-defined
                spec = CAdbCompressionSpec.from_buffer_copy(mm, 4)
                match spec.alg:
                    case AdbCompressionAlg.NONE:
                        body = mm
                        offset = 6
                    case AdbCompressionAlg.DEFLATE:
                        body = zlib.decompress(mm[6:], wbits=-15)
                        if body[0:3] != b"ADB":
                            panic("Inner deflate stream is not an APK", FormatError)
                        offset = 4
                        stack.close()
                        del mm
                        del f
                    case AdbCompressionAlg.ZSTD:
                        body = zstd.decompress(mm[6:])
                        if body[0:3] != b"ADB":
                            panic("Inner zstd stream is not an APK", FormatError)
                        offset = 4
                        stack.close()
                        del mm
                        del f
                    case _:
                        panic(f"Invalid compression alg ID {spec.alg} (level {spec.level}) ", FormatError)
                del spec
            case _:
                panic(f"Invalid compression magic {mm[3]:x}", FormatError)
        size = len(body)

        mode_tar = "w:"
        if path_tar:
            if path_tar.name.endswith((".gz", ".bz2", ".xz", ".zst")):
                mode_tar += path_tar.name.rsplit(".", 1)[-1]
        else:
            path_tar = Path("/dev/null")

        tar = stack.enter_context(
            tarfile.open(path_tar, mode_tar) # type: ignore
        )

        f_meta = stack.enter_context((path_meta or Path("/dev/null")).open("w"))
        meta_schemas: list[dict[str, object]] = []
        meta_doc: dict[str, object] = {
            "apk": str(path_apk),
            "schemas": meta_schemas,
        }

        while offset < size:
            if offset + SZ_CADB_SCHEMA > size:
                panic(f"Truncated schema at offset {offset}", FormatError)
            schema = CAdbSchema.from_buffer_copy(body, offset).value
            offset += SZ_CADB_SCHEMA

            match schema:
                case AdbSchema.PACKAGE:
                    logger.info("Schema: package")
                    offset = _dump_blocks(body, offset, size, schema, tar, meta_schemas)
                case AdbSchema.INDEX:
                    panic("Schema for index is not supported yet", NotImplementedError)
                case _:
                    panic(f"Unknown schema {schema:#x}", FormatError)

        json.dump(meta_doc, f_meta, indent=2, sort_keys=True)
        f_meta.write("\n")


if __name__ == "__main__":
    logging._levelToName = {
        logging.DEBUG:      '\33[37mDEBUG...\33[0m',
        logging.INFO:       '\33[36mINFO....\33[0m',
        logging.WARNING:    '\33[33mWARNING!\33[0m',
        logging.ERROR:      '\33[35mERROR!!!\33[0m',
        logging.FATAL:      '\33[31mFATAL!!!\33[0m',
        logging.NOTSET:            '........',
    }
    logging.basicConfig(stream=sys.stdout, format="%(levelname)s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--tar", type=Path, help="Convert the apk into a tar")
    parser.add_argument("--meta", type=Path, help="Dump the metadata JSON into said file")
    args = parser.parse_args()

    logger.info(f"Dumping APK '{args.apk}'")
    dump(args.apk, args.tar, args.meta)
