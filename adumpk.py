#!/usr/bin/env python3
from abc import ABC, abstractmethod
import argparse
import ctypes
from ctypes import LittleEndianStructure
from compression import zstd
from enum import Enum, IntEnum
import io
import json
import logging
from pathlib import PosixPath as Path
import stat
import sys
import tarfile
from typing import BinaryIO, Literal, NoReturn, Optional, Type, TypedDict
import zlib

logger = logging.getLogger(__name__)

class FormatError(ValueError):
    pass

def panic(msg: str, etype: Type[Exception] = ValueError) -> NoReturn:
    logger.fatal(msg)
    raise etype(msg)

# Int Enums instead of global variables
class AdbCompressionWay(IntEnum):
    NONE = 0x2e # .
    DEFLATE = 0x64 # d
    CUSTOM = 0x63 # c

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

class AdbPkgInfoType(IntEnum):
    NAME = 1
    VERSION = 2
    HASHES = 3
    DESCRIPTION =4
    ARCH = 5
    LICENSE= 6
    ORIGIN = 7
    MAINTAINER = 8
    URL = 9
    REPO_COMMIT = 10
    BUILD_TIME = 11
    INSTALLED_SIZE = 12
    FILE_SIZE = 13
    PROVIDER_PRIORITY = 14
    DEPENDS = 15
    PROVIDES = 16
    REPLACES = 17
    INSTALL_IF = 18
    RECOMMENDS = 19
    LAYER = 20
    TAGS = 21

    def __str__(self) -> str:
        if self < self.NAME or self > self.TAGS:
            panic(f"Invalid enum type {int(self)}", ValueError)
        return (
            "name",
            "version",
            "hashes",
            "description",
            "arch",
            "license",
            "origin",
            "maintainer",
            "url",
            "repo-commit",
            "build-time",
            "installed-size",
            "file-size",
            "provider-priority",
            "depends",
            "provides",
            "replaces",
            "install-if",
            "recommends",
            "layer",
            "tags",
        )[self - 1]

# C type aliases
Cu8 = ctypes.c_uint8
Cu16 = ctypes.c_uint16
Cu32 = ctypes.c_uint32
Cu64 = ctypes.c_uint64
CAdbSchema = Cu32

class CAdbCompressionSpec(LittleEndianStructure):
    _fields_ = (("alg",   Cu8),
                ("level", Cu8))

class CAdbBlock(LittleEndianStructure):
    _fields_ = (("type_size", Cu32),
                ("reserved", Cu32),
                ("x_size", Cu64))

class CAdbHdr(LittleEndianStructure):
    _fields_ = (("adb_compat_ver", Cu8),
                ("adb_ver", Cu8),
                ("reserved", Cu16),
                ("root", Cu32))

class CAdbSignHdr(LittleEndianStructure):
    _fields_ = (("sign_ver", Cu8),
                ("hash_alg", Cu8))

class CAdbDataPackage(LittleEndianStructure):
    _fields_ = (("path_idx", Cu32),
                ("file_idx", Cu32))

# Cached size constants for hot-path parsing
SZ_CU8 = ctypes.sizeof(Cu8)
SZ_CU16 = ctypes.sizeof(Cu16)
SZ_CU32 = ctypes.sizeof(Cu32)
SZ_CU64 = ctypes.sizeof(Cu64)
SZ_CADB_SCHEMA = ctypes.sizeof(CAdbSchema)
SZ_CADB_BLOCK = ctypes.sizeof(CAdbBlock)
SZ_CADB_HDR = ctypes.sizeof(CAdbHdr)
SZ_CADB_SIGN_HDR = ctypes.sizeof(CAdbSignHdr)
SZ_CADB_DATA_PACKAGE = ctypes.sizeof(CAdbDataPackage)

PkgMetaValue = int | str | list[str]
PackageMetadata = dict[str, PkgMetaValue]

class FileKind(str, Enum):
    FILE = "file"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    SPECIAL = "special"
    UNKNOWN = "unknown"

class DirectoryEntry(TypedDict):
    path: str
    mode: int
    user: Optional[str]
    group: Optional[str]
    path_idx: int

class FileEntry(TypedDict):
    path: str
    name: str
    path_idx: int
    file_idx: int
    kind: FileKind
    size: int
    mtime: int
    mode: int
    user: Optional[str]
    group: Optional[str]
    link_target: Optional[str]
    device: Optional[int]

class PackageSchemaMeta(TypedDict):
    schema: Literal["package"]
    metadata: PackageMetadata
    dirs: list[DirectoryEntry]
    files: list[FileEntry]

class ApkByteStream(ABC):
    @abstractmethod
    def read(self, size: int) -> bytes:
        raise NotImplementedError

    def read_exact(self, size: int, what: str) -> bytes:
        if size <= 0:
            return b""
        out = bytearray()
        while len(out) < size:
            chunk = self.read(size - len(out))
            if not chunk:
                panic(f"Truncated {what}", FormatError)
            out.extend(chunk)
        return bytes(out)

    def read_exact_or_none(self, size: int, what: str) -> Optional[bytes]:
        first = self.read(size)
        if not first:
            return None
        if len(first) == size:
            return first
        out = bytearray(first)
        while len(out) < size:
            chunk = self.read(size - len(out))
            if not chunk:
                panic(f"Truncated {what}", FormatError)
            out.extend(chunk)
        return bytes(out)

    def skip(self, size: int, what: str):
        remaining = size
        while remaining > 0:
            chunk = self.read(min(remaining, 1024 * 1024))
            if not chunk:
                panic(f"Truncated {what}", FormatError)
            remaining -= len(chunk)

    def close(self):
        pass

class RawApkByteStream(ApkByteStream):
    def __init__(self, f: BinaryIO):
        self._f = f

    def read(self, size: int) -> bytes:
        return self._f.read(size)

class DeflateApkByteStream(ApkByteStream):
    def __init__(self, f: BinaryIO):
        self._f = f
        self._dec = zlib.decompressobj(wbits=-15)
        self._out = bytearray()
        self._eof = False

    def _fill(self, size: int):
        while len(self._out) < size and not self._eof:
            in_chunk = self._f.read(1024 * 1024)
            if not in_chunk:
                self._out.extend(self._dec.flush())
                self._eof = True
                break
            self._out.extend(self._dec.decompress(in_chunk))

    def read(self, size: int) -> bytes:
        if size <= 0:
            return b""
        self._fill(size)
        out = bytes(self._out[:size])
        del self._out[:len(out)]
        return out

class ZstdApkByteStream(ApkByteStream):
    def __init__(self, f: BinaryIO):
        self._f = f
        self._dec = zstd.ZstdDecompressor()
        self._out = bytearray()
        self._done = False

    def _fill(self, size: int):
        while len(self._out) < size and not self._done:
            if self._dec.needs_input:
                in_chunk = self._f.read(1024 * 1024)
                if not in_chunk:
                    panic("Truncated zstd stream", FormatError)
            else:
                in_chunk = b""

            out_chunk = self._dec.decompress(in_chunk, max_length=1024 * 1024)
            if out_chunk:
                self._out.extend(out_chunk)
            elif self._dec.needs_input and not in_chunk:
                panic("Truncated zstd stream", FormatError)

            if self._dec.eof:
                self._done = True
                break

    def read(self, size: int) -> bytes:
        if size <= 0:
            return b""
        self._fill(size)
        out = bytes(self._out[:size])
        del self._out[:len(out)]
        return out

class ApkBodySource:
    def __init__(self, f: BinaryIO, stream: ApkByteStream):
        self._f = f
        self.stream = stream
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        self.stream.close()
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    @staticmethod
    def assert_head(head: bytes, what: str):
        if head[0:3] != b"ADB":
            panic(f"{what} is not an APK", FormatError)

    @staticmethod
    def assert_header(stream: ApkByteStream, what: str):
        head = stream.read_exact(4, f"{what} header")
        ApkBodySource.assert_head(head, what)

    @classmethod
    def open(cls, path_apk: Path) -> "ApkBodySource":
        f = path_apk.open("rb")
        try:
            head = f.read(6)
            if len(head) < 4:
                panic("File too small, meanless to dump")
            cls.assert_head(head, "File")

            match head[3]:
                case AdbCompressionWay.NONE:
                    f.seek(4)
                    return cls(f, RawApkByteStream(f))
                case AdbCompressionWay.DEFLATE:
                    f.seek(4)
                    stream = DeflateApkByteStream(f)
                    cls.assert_header(stream, "Inner deflate stream")
                    return cls(f, stream)
                case AdbCompressionWay.CUSTOM:
                    if len(head) < 6:
                        panic("Truncated custom compression spec", FormatError)
                    spec = CAdbCompressionSpec.from_buffer_copy(head, 4)
                    match spec.alg:
                        case AdbCompressionAlg.NONE:
                            f.seek(6)
                            return cls(f, RawApkByteStream(f))
                        case AdbCompressionAlg.DEFLATE:
                            f.seek(6)
                            stream = DeflateApkByteStream(f)
                            cls.assert_header(stream, "Inner deflate stream")
                            return cls(f, stream)
                        case AdbCompressionAlg.ZSTD:
                            f.seek(6)
                            stream = ZstdApkByteStream(f)
                            cls.assert_header(stream, "Inner zstd stream")
                            return cls(f, stream)
                        case _:
                            panic(f"Invalid compression alg ID {spec.alg} (level {spec.level}) ", FormatError)
                case _:
                    panic(f"Invalid compression magic {head[3]:x}", FormatError)
        except Exception:
            f.close()
            raise
        panic("Unreachable compression state", RuntimeError)

class AdbReader:
    VAL_TYPE_MASK = 0xF0000000
    VAL_DATA_MASK = 0x0FFFFFFF
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
        if off + SZ_CU16 > len(self.adb):
            panic(f"Truncated u16 at offset {off}", FormatError)
        return Cu16.from_buffer_copy(self.adb, off).value

    def _u32(self, off: int) -> int:
        if off + SZ_CU32 > len(self.adb):
            panic(f"Truncated u32 at offset {off}", FormatError)
        return Cu32.from_buffer_copy(self.adb, off).value

    def _u64(self, off: int) -> int:
        if off + SZ_CU64 > len(self.adb):
            panic(f"Truncated u64 at offset {off}", FormatError)
        return Cu64.from_buffer_copy(self.adb, off).value

    def read_int(self, v: int) -> Optional[int]:
        t = self._val_type(v)
        off = self._val_data(v)
        match t:
            case AdbValType.INT:
                return off
            case AdbValType.INT32:
                return self._u32(off)
            case AdbValType.INT64:
                return self._u64(off)
            case _:
                return None

    def read_blob(self, v: int) -> Optional[bytes]:
        t = self._val_type(v)
        off = self._val_data(v)
        match t:
            case AdbValType.BLOB8:
                if off >= len(self.adb):
                    panic(f"Truncated blob8 length at offset {off}", FormatError)
                length = self.adb[off]
                start = off + 1
            case AdbValType.BLOB16:
                length = self._u16(off)
                start = off + 2
            case AdbValType.BLOB32:
                length = self._u32(off)
                start = off + 4
            case _:
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

    def _parse_dep(self, dep_tag: int) -> Optional[str]:
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

    def _parse_dep_array(self, arr_tag: int) -> list[str]:
        out = []
        arr = self.read_obj(arr_tag)
        for i in range(1, len(arr)):
            tag = arr[i]
            if tag == 0:
                continue
            dep = self._parse_dep(tag)
            if dep is not None:
                out.append(dep)
        return out

    def _parse_string_array(self, arr_tag: int) -> list[str]:
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

    def _parse_pkginfo(self, pkginfo_tag: int) -> PackageMetadata:
        meta: PackageMetadata = {}
        obj = self.read_obj(pkginfo_tag)
        for idx in range(1, len(obj)):
            tag = obj[idx]
            if tag == 0:
                continue
            name = str(AdbPkgInfoType(idx))
            if idx in self.PKGINFO_DEP_FIELDS:
                meta[name] = self._parse_dep_array(tag)
                continue
            if idx == int(AdbPkgInfoField.TAGS):
                meta[name] = self._parse_string_array(tag)
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
                text = self.blob_to_text(blob)
                if text is not None:
                    meta[name] = text
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
    def _parse_target_blob(target: Optional[bytes]) -> tuple[FileKind, Optional[str], Optional[int]]:
        if not target:
            return FileKind.FILE, None, None
        if len(target) < 2:
            panic("Invalid target blob too short", FormatError)
        tmode = int.from_bytes(target[0:2], "little")
        payload = target[2:]
        ftype = stat.S_IFMT(tmode)
        if ftype == stat.S_IFLNK:
            try:
                return FileKind.SYMLINK, payload.decode("utf-8"), None
            except UnicodeDecodeError:
                return FileKind.SYMLINK, payload.decode("utf-8", errors="surrogateescape"), None
        if ftype == stat.S_IFREG:
            try:
                return FileKind.HARDLINK, payload.decode("utf-8"), None
            except UnicodeDecodeError:
                return FileKind.HARDLINK, payload.decode("utf-8", errors="surrogateescape"), None
        if ftype in (stat.S_IFBLK, stat.S_IFCHR, stat.S_IFIFO):
            if len(payload) != 8:
                panic("Invalid device/fifo target blob length", FormatError)
            return FileKind.SPECIAL, None, int.from_bytes(payload, "little")
        return FileKind.UNKNOWN, None, None

    def parse_package(self) -> tuple[PackageMetadata, list[DirectoryEntry], list[FileEntry], dict[tuple[int, int], FileEntry]]:
        if len(self.adb) < SZ_CADB_HDR:
            panic("ADB payload too small for header", FormatError)
        hdr = CAdbHdr.from_buffer_copy(self.adb, 0)
        pkg = self.read_obj(hdr.root)

        metadata: PackageMetadata = {}
        pkginfo_tag = self.obj_get(pkg, AdbPkgField.PKGINFO)
        if pkginfo_tag != 0:
            metadata = self._parse_pkginfo(pkginfo_tag)

        dirs: list[DirectoryEntry] = []
        file_entries: list[FileEntry] = []
        file_lookup: dict[tuple[int, int], FileEntry] = {}
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
                info: FileEntry = {
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

class _TarDataStream:
    def __init__(self, stream: ApkByteStream, size: int):
        self._stream = stream
        self._remaining = size

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size < 0 or size > self._remaining:
            size = self._remaining
        data = self._stream.read_exact(size, "DATA payload")
        self._remaining -= len(data)
        return data

class TarEmitter:
    def __init__(self, tar: tarfile.TarFile):
        self.tar = tar
        self.seen_dirs: set[str] = set()

    def _add_parent_dirs(self, path: str):
        parts = Path(path).parts[:-1]
        current = ""
        for part in parts:
            current = f"{current}/{part}" if current else part
            if current in self.seen_dirs:
                continue
            ti = _tarinfo_base(f"{current}/", 0o755, 0)
            ti.type = tarfile.DIRTYPE
            ti.size = 0
            self.tar.addfile(ti)
            self.seen_dirs.add(current)

    def add_dir(self, d: DirectoryEntry):
        path = d["path"]
        if not path or path in self.seen_dirs:
            return
        self._add_parent_dirs(path)
        ti = _tarinfo_base(f"{path}/", d["mode"], 0)
        ti.type = tarfile.DIRTYPE
        ti.size = 0
        self.tar.addfile(ti)
        self.seen_dirs.add(path)

    def add_nondata_file(self, f: FileEntry):
        kind = f["kind"]
        path = f["path"]
        self._add_parent_dirs(path)
        match kind:
            case FileKind.FILE:
                if f["size"] == 0:
                    ti = _tarinfo_base(path, f["mode"], f["mtime"])
                    ti.size = 0
                    self.tar.addfile(ti, io.BytesIO())
            case FileKind.SYMLINK:
                ti = _tarinfo_base(path, f["mode"], f["mtime"])
                ti.type = tarfile.SYMTYPE
                ti.linkname = f["link_target"] or ""
                ti.size = 0
                self.tar.addfile(ti)
            case FileKind.HARDLINK:
                ti = _tarinfo_base(path, f["mode"], f["mtime"])
                ti.type = tarfile.LNKTYPE
                ti.linkname = f["link_target"] or ""
                ti.size = 0
                self.tar.addfile(ti)

    def add_data_file_stream(self, f: FileEntry, data_len: int, stream: ApkByteStream):
        path = f["path"]
        self._add_parent_dirs(path)
        ti = _tarinfo_base(path, f["mode"], f["mtime"])
        ti.size = data_len
        self.tar.addfile(ti, _TarDataStream(stream, data_len))

class ApkDumper:
    def __init__(self, stream: ApkByteStream, tar: tarfile.TarFile, meta_schemas: list[PackageSchemaMeta]):
        self.stream = stream
        self.tar_writer = TarEmitter(tar)
        self.meta_schemas = meta_schemas

    def _parse_block(self) -> Optional[tuple[int, int, int]]:
        type_size_raw = self.stream.read_exact_or_none(SZ_CU32, "block type/size")
        if type_size_raw is None:
            return None

        type_size = Cu32.from_buffer_copy(type_size_raw, 0).value
        block_type = type_size >> 30
        if block_type == AdbBlockType.EXT:
            ext = self.stream.read_exact(SZ_CADB_BLOCK - SZ_CU32, "extended block header")
            blk = CAdbBlock.from_buffer_copy(type_size_raw + ext, 0)
            block_type = type_size & 0x3fffffff
            raw_size = blk.x_size
            hdr_size = SZ_CADB_BLOCK
        else:
            raw_size = type_size & 0x3fffffff
            hdr_size = SZ_CU32

        if raw_size < hdr_size:
            panic(f"Invalid block raw size {raw_size}", FormatError)

        payload_size = raw_size - hdr_size
        pad_size = ((raw_size + 8 - 1) // 8 * 8) - raw_size
        return block_type, payload_size, pad_size

    def _dump_blocks(self, schema: int):
        seen_adb = False
        seen_data = False
        file_lookup: dict[tuple[int, int], FileEntry] = {}
        written_data: set[tuple[int, int]] = set()
        index = 0

        while True:
            blk = self._parse_block()
            if blk is None:
                break
            block_type, payload_size, pad_size = blk

            match block_type:
                case AdbBlockType.ADB:
                    if seen_adb or seen_data:
                        panic("Invalid block order: ADB block after SIG/DATA", FormatError)
                    if payload_size < SZ_CADB_HDR:
                        panic("ADB block payload too small", FormatError)
                    adb_payload = self.stream.read_exact(payload_size, "ADB block payload")
                    adb_hdr = CAdbHdr.from_buffer_copy(adb_payload, 0)
                    logger.info(
                        f"  [{index}] ADB payload={payload_size} compat={adb_hdr.adb_compat_ver} ver={adb_hdr.adb_ver}"
                    )
                    if schema == AdbSchema.PACKAGE:
                        metadata, dirs, files, file_lookup = AdbReader(
                            adb_payload
                        ).parse_package()
                        self.meta_schemas.append({
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
                            self.tar_writer.add_dir(d)
                        for f in files:
                            self.tar_writer.add_nondata_file(f)
                    seen_adb = True
                case AdbBlockType.SIG:
                    if not seen_adb or seen_data:
                        panic("Invalid block order: SIG block position", FormatError)
                    if payload_size < SZ_CADB_SIGN_HDR:
                        panic("SIG block payload too small", FormatError)
                    sig_payload = self.stream.read_exact(payload_size, "SIG block payload")
                    sig = CAdbSignHdr.from_buffer_copy(sig_payload, 0)
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
                        data_hdr = self.stream.read_exact(SZ_CADB_DATA_PACKAGE, "DATA block package header")
                        hdr = CAdbDataPackage.from_buffer_copy(data_hdr, 0)
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

                        if file_info["kind"] != FileKind.FILE:
                            panic(f"DATA block points to non-regular file '{file_info['path']}'", FormatError)
                        if data_len != file_info["size"]:
                            panic(
                                f"DATA size mismatch for '{file_info['path']}': {data_len} != {file_info['size']}",
                                FormatError,
                            )
                        self.tar_writer.add_data_file_stream(file_info, data_len, self.stream)
                    else:
                        logger.info(f"  [{index}] DATA payload={payload_size}")
                        self.stream.skip(payload_size, "DATA payload")
                case _:
                    panic(f"Unknown block type {block_type}", FormatError)

            if pad_size:
                self.stream.skip(pad_size, "block padding")
            index += 1

        if not seen_adb:
            panic("ADB stream did not contain an ADB block", FormatError)

    def run(self):
        while True:
            schema_raw = self.stream.read_exact_or_none(SZ_CADB_SCHEMA, "schema")
            if schema_raw is None:
                break
            schema = CAdbSchema.from_buffer_copy(schema_raw, 0).value

            match schema:
                case AdbSchema.PACKAGE:
                    logger.info("Schema: package")
                    self._dump_blocks(schema)
                case AdbSchema.INDEX:
                    panic("Schema for index is not supported yet", NotImplementedError)
                case _:
                    panic(f"Unknown schema {schema:#x}", FormatError)

def dump(path_apk: Path, path_tar: Optional[Path], path_meta: Optional[Path]):
    with ApkBodySource.open(path_apk) as src:
        stream = src.stream

        mode_tar = "w:"
        if path_tar:
            if path_tar.name.endswith((".gz", ".bz2", ".xz", ".zst")):
                mode_tar += path_tar.name.rsplit(".", 1)[-1]
        else:
            path_tar = Path("/dev/null")

        with tarfile.open(path_tar, mode_tar) as tar, (path_meta or Path("/dev/null")).open("w") as f_meta: # type: ignore[arg-type]
            meta_schemas: list[PackageSchemaMeta] = []
            meta_doc: dict[str, str | list[PackageSchemaMeta]] = {
                "apk": str(path_apk),
                "schemas": meta_schemas,
            }
            ApkDumper(stream, tar, meta_schemas).run()

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
