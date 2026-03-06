#!/usr/bin/env python3
from abc import ABC, abstractmethod
import argparse
import ctypes
from ctypes import LittleEndianStructure
try:
    from compression import zstd
except ModuleNotFoundError:
    zstd = None
from dataclasses import asdict, dataclass, field
from enum import IntEnum, StrEnum
import io
import json
import logging
import os
from pathlib import PosixPath as Path
import stat
import sys
import tarfile
from typing import BinaryIO, NoReturn, Optional, Type
import zlib

logger = logging.getLogger(__name__)

class FormatError(ValueError):
    pass

def panic(msg: str, etype: Type[Exception] = ValueError) -> NoReturn:
    logger.fatal(msg)
    raise etype(msg)

# Int Enums instead of global variables
class AdbCompressionWay(IntEnum):
    NONE    = 0x2e  # .
    DEFLATE = 0x64  # d
    CUSTOM  = 0x63  # c

class AdbCompressionAlg(IntEnum):
    NONE    = 0
    DEFLATE = 1
    ZSTD    = 2

class AdbSchema(IntEnum):
    PACKAGE = 0x676B6370
    INDEX   = 0x78646E69

class AdbBlockType(IntEnum):
    ADB  = 0
    SIG  = 1
    DATA = 2
    EXT  = 3

class AdbValType(IntEnum):
    SPECIAL = 0x00000000
    INT     = 0x10000000
    INT32   = 0x20000000
    INT64   = 0x30000000
    BLOB8   = 0x80000000
    BLOB16  = 0x90000000
    BLOB32  = 0xA0000000
    ARRAY   = 0xD0000000
    OBJECT  = 0xE0000000

class AdbField(IntEnum):
    pass

class AdbPkgField(AdbField):
    PKGINFO = 1
    PATHS   = 2

class AdbPkgInfoField(AdbField):
    NAME              = 1
    VERSION           = 2
    HASHES            = 3
    DESCRIPTION       = 4
    ARCH              = 5
    LICENSE           = 6
    ORIGIN            = 7
    MAINTAINER        = 8
    URL               = 9
    REPO_COMMIT       = 10
    BUILD_TIME        = 11
    INSTALLED_SIZE    = 12
    FILE_SIZE         = 13
    PROVIDER_PRIORITY = 14
    DEPENDS           = 15
    PROVIDES          = 16
    REPLACES          = 17
    INSTALL_IF        = 18
    RECOMMENDS        = 19
    LAYER             = 20
    TAGS              = 21

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

class AdbDirField(AdbField):
    NAME  = 1
    ACL   = 2
    FILES = 3

class AdbFileField(AdbField):
    NAME   = 1
    ACL    = 2
    SIZE   = 3
    MTIME  = 4
    HASHES = 5
    TARGET = 6

class AdbDepField(AdbField):
    NAME    = 1
    VERSION = 2
    MATCH   = 3

class AdbAclField(AdbField):
    MODE   = 1
    USER   = 2
    GROUP  = 3
    XATTRS = 4

class ApkVersionFlag(IntEnum):
    EQUAL    = 0b00001 # 1 << 0
    LESS     = 0b00010 # 1 << 1
    GREATER  = 0b00100 # 1 << 2
    FUZZY    = 0b01000 # 1 << 3
    CONFLICT = 0b10000 # 1 << 4

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

class FileKind(StrEnum):
    FILE = "file"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    BLOCK = "block"
    CHAR = "char"
    FIFO = "fifo"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class DirectoryEntry:
    path: str
    mode: int
    user: Optional[str]
    group: Optional[str]
    path_idx: int
    xattrs: list["XattrEntry"] = field(default_factory=list)

@dataclass(frozen=True)
class XattrEntry:
    name: str
    value_hex: str
    value_text: Optional[str]

@dataclass(frozen=True)
class FileEntry:
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
    xattrs: list[XattrEntry] = field(default_factory=list)
    hash_alg: Optional[str] = None
    hash_hex: Optional[str] = None

@dataclass(frozen=True)
class PackageSchemaMeta:
    schema: str = field(default="package", init=False)
    metadata: PackageMetadata
    dirs: list[DirectoryEntry]
    files: list[FileEntry]

SZ_CHUNK = 1024 * 1024 # 1 MiB

class AdbStream(ABC):
    @abstractmethod
    def read(self, size: int) -> bytearray:
        raise NotImplementedError

    def _read_exact_inner(self, size: int, what: str, out: bytearray) -> bytearray:
        len_out = len(out)
        while True:
            chunk = self.read(size - len_out)
            if not chunk:
                panic(f"Truncated {what}", FormatError)
            out.extend(chunk)
            len_out = len(out)
            if len_out == size:
                return out
            elif len_out > size:
                panic(f"More {what} read than expected, {len_out} > {size}", IOError)

    def read_exact(self, size: int, what: str) -> bytearray:
        if size <= 0:
            return bytearray()
        return self._read_exact_inner(size, what, bytearray())

    def read_exact_or_none(self, size: int, what: str) -> Optional[bytearray]:
        first = self.read(size)
        if not first:
            return None
        if len(first) == size:
            return first
        return self._read_exact_inner(size, what, first)

    def skip(self, size: int, what: str):
        remaining = size
        while remaining > 0:
            chunk = self.read(min(remaining, SZ_CHUNK))
            if not chunk:
                panic(f"Truncated {what}", FormatError)
            remaining -= len(chunk)

    def close(self):
        pass

class RawAdbStream(AdbStream):
    __slots__ = ("_file")

    def __init__(self, file: io.BufferedReader):
        self._file = file

    def read(self, size: int) -> bytearray:
        buffer = bytearray(size)
        len_read = self._file.readinto(buffer)
        del(buffer[len_read:])
        return buffer

class _RingBuffer:
    __slots__ = ("_buffer", "_head", "_size")

    def __init__(self, capacity: int = SZ_CHUNK): # Default size 1 MiB
        self._buffer = bytearray(capacity)
        self._head = 0
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def _ensure_capacity(self, required: int):
        new_capacity = len(self._buffer)
        if new_capacity >= required:
            return
        while new_capacity < required:
            new_capacity *= 2
        new_buffer = bytearray(new_capacity)
        if self._size > 0:
            size_first = min(self._size, new_capacity - self._head)
            new_buffer[0:size_first] = self._buffer[self._head:self._head+size_first]
            size_second = self._size - size_first
            if size_second > 0:
                new_buffer[size_first:size_first+size_second] = self._buffer[0:size_second]
        self._buffer = new_buffer
        self._head = 0

    def write(self, data: bytes | bytearray):
        if not data:
            return
        len_data = len(data)
        new_size = self._size + len_data
        self._ensure_capacity(new_size)
        len_buffer = len(self._buffer)
        tail = (self._head + self._size) % len_buffer
        size_first = min(len_data, len_buffer - tail)
        self._buffer[tail:tail+size_first] = data[0:size_first]
        size_second = len_data - size_first
        if size_second > 0:
            self._buffer[0:size_second] = data[size_first:size_first+size_second]
        self._size = new_size

    def read(self, size: int) -> bytearray:
        if size <= 0 or self._size == 0:
            return bytearray()
        len_out = min(size, self._size)
        len_buffer = len(self._buffer)
        size_first = min(len_out, len_buffer - self._head)
        out = self._buffer[self._head:self._head+size_first]
        if size_first < len_out:
            out += self._buffer[0:len_out-size_first]
        self._head = (self._head + len_out) % len_buffer
        self._size -= len_out
        return out


class DeflateAdbStream(AdbStream):
    __slots__ = ("_file", "_decompressor", "_buffer", "_eof")

    def __init__(self, file: BinaryIO):
        self._file = file
        self._decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        self._buffer = _RingBuffer()
        self._eof = False

    def _fill(self, size: int):
        while self._buffer._size < size and not self._eof:
            in_chunk = self._file.read(SZ_CHUNK)
            if not in_chunk:
                self._buffer.write(
                    self._decompressor.flush()
                )
                self._eof = True
                break
            self._buffer.write(
                self._decompressor.decompress(in_chunk)
            )

    def read(self, size: int) -> bytearray:
        if size <= 0:
            return bytearray()
        self._fill(size)
        return self._buffer.read(size)

class ZstdAdbStream(AdbStream):
    __slots__ = ("_file", "_decompressor", "_buffer", "_eof")

    def __init__(self, file: BinaryIO):
        if zstd is None:
            panic("Zstd module was not imported")
        self._file = file
        self._decompressor = zstd.ZstdDecompressor()
        self._buffer = _RingBuffer()
        self._eof = False

    def _fill(self, size: int):
        while self._buffer._size < size and not self._eof:
            if self._decompressor.needs_input:
                in_chunk = self._file.read(SZ_CHUNK)
                if not in_chunk:
                    panic("Truncated zstd stream", FormatError)
            else:
                in_chunk = b""

            out_chunk = self._decompressor.decompress(in_chunk)
            if out_chunk:
                self._buffer.write(out_chunk)
            elif self._decompressor.needs_input and not in_chunk:
                panic("Truncated zstd stream", FormatError)

            if self._decompressor.eof:
                self._eof = True
                break

    def read(self, size: int) -> bytearray:
        if size <= 0:
            return bytearray()
        self._fill(size)
        return self._buffer.read(size)

class ApkBodySource:
    def __init__(self, f: BinaryIO, stream: AdbStream):
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
    def assert_header(stream: AdbStream, what: str):
        head = stream.read_exact(4, f"{what} header")
        ApkBodySource.assert_head(bytes(head), what)

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
                    return cls(f, RawAdbStream(f))
                case AdbCompressionWay.DEFLATE:
                    f.seek(4)
                    stream = DeflateAdbStream(f)
                    cls.assert_header(stream, "Inner deflate stream")
                    return cls(f, stream)
                case AdbCompressionWay.CUSTOM:
                    if len(head) < 6:
                        panic("Truncated custom compression spec", FormatError)
                    spec = CAdbCompressionSpec.from_buffer_copy(head, 4)
                    match spec.alg:
                        case AdbCompressionAlg.NONE:
                            f.seek(6)
                            return cls(f, RawAdbStream(f))
                        case AdbCompressionAlg.DEFLATE:
                            f.seek(6)
                            stream = DeflateAdbStream(f)
                            cls.assert_header(stream, "Inner deflate stream")
                            return cls(f, stream)
                        case AdbCompressionAlg.ZSTD:
                            if zstd is None:
                                panic("Zstd compression not supported on current Python installation")
                            f.seek(6)
                            stream = ZstdAdbStream(f)
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
    __slots__ = ("adb",)

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

    def __init__(self, adb_payload: bytearray):
        self.adb = adb_payload

    # The highest 4 bits in a value mark is type, as defined in AdbValType
    def _val_type(self, v: int) -> int:
        return v & 0xF0000000

    # The lowest 28 bits in a value mark is type, as defined in AdbValType
    def _val_data(self, v: int) -> int:
        return v & 0x0FFFFFFF

    def _u16(self, off: int) -> int:
        if off + SZ_CU16 > len(self.adb):
            panic(f"Truncated u16 at offset {off}", FormatError)
        return Cu16.from_buffer(self.adb, off).value

    def _u32(self, off: int) -> int:
        if off + SZ_CU32 > len(self.adb):
            panic(f"Truncated u32 at offset {off}", FormatError)
        return Cu32.from_buffer(self.adb, off).value

    def _u64(self, off: int) -> int:
        if off + SZ_CU64 > len(self.adb):
            panic(f"Truncated u64 at offset {off}", FormatError)
        return Cu64.from_buffer(self.adb, off).value

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
        return [Cu32.from_buffer(self.adb, off + i * SZ_CU32).value for i in range(num)]

    @staticmethod
    def obj_get(obj: list[int], index: AdbField) -> int:
        if index < len(obj):
            return obj[index]
        return 0

    @staticmethod
    def blob_to_text(blob: Optional[bytes]) -> Optional[str]:
        if blob is None:
            return None
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            return blob.hex()

    def _parse_dep(self, dep_tag: int) -> Optional[str]:
        dep = self.read_obj(dep_tag)
        name = self.blob_to_text(self.read_blob(self.obj_get(dep, AdbDepField.NAME)))
        ver = self.blob_to_text(self.read_blob(self.obj_get(dep, AdbDepField.VERSION)))
        op = self.read_int(self.obj_get(dep, AdbDepField.MATCH))
        if name is None:
            return None
        if ver:
            if op:
                match op & ~ApkVersionFlag.CONFLICT:
                    case int(ApkVersionFlag.LESS):
                        sign = "<"
                    case int(ApkVersionFlag.LESS | ApkVersionFlag.EQUAL):
                        sign = "<="
                    case int(ApkVersionFlag.LESS | ApkVersionFlag.EQUAL | ApkVersionFlag.FUZZY):
                        sign = "<~"
                    case int(ApkVersionFlag.FUZZY):
                        sign = "~"
                    case int(ApkVersionFlag.EQUAL):
                        sign = "="
                    case int(ApkVersionFlag.GREATER | ApkVersionFlag.EQUAL):
                        sign = ">="
                    case int(ApkVersionFlag.GREATER | ApkVersionFlag.EQUAL | ApkVersionFlag.FUZZY):
                        sign = ">~"
                    case int(ApkVersionFlag.GREATER):
                        sign = ">"
                    case _:
                        panic(f"Invalid dep op {op}")
                return f"{'!' if op & ApkVersionFlag.CONFLICT else ''}{name}{sign}{ver}"
            else:
                return f"{name}={ver}"
        else:
            return ("!" if op and op & ApkVersionFlag.CONFLICT else "") + name

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
            name = str(AdbPkgInfoField(idx))
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

    def _parse_xattrs(self, xattr_tag: int) -> list[XattrEntry]:
        if xattr_tag == 0:
            return []
        out: list[XattrEntry] = []
        arr = self.read_obj(xattr_tag)
        for i in range(1, len(arr)):
            tag = arr[i]
            if tag == 0:
                continue
            blob = self.read_blob(tag)
            if blob is None:
                continue
            sep = blob.find(b"\x00")
            if sep < 0:
                panic("Invalid ACL xattr entry missing NUL separator", FormatError)
            name_raw = blob[:sep]
            value_raw = blob[sep + 1:]
            name = self.blob_to_text(name_raw)
            if name is None:
                panic("Invalid ACL xattr name", FormatError)
            out.append(XattrEntry(
                name=name,
                value_hex=value_raw.hex(),
                value_text=self.blob_to_text(value_raw),
            ))
        return out

    @staticmethod
    def _parse_hash(hash_blob: Optional[bytes]) -> tuple[Optional[str], Optional[str]]:
        if not hash_blob:
            return None, None
        alg = {
            20: "SHA1",
            32: "SHA256",
            64: "SHA512",
        }.get(len(hash_blob))
        return alg, hash_blob.hex()

    def _parse_acl(self, acl_tag: int, default_mode: int) -> tuple[int, Optional[str], Optional[str], list[XattrEntry]]:
        if acl_tag == 0:
            return default_mode, None, None, []
        acl = self.read_obj(acl_tag)
        mode = self.read_int(self.obj_get(acl, AdbAclField.MODE))
        user = self.blob_to_text(self.read_blob(self.obj_get(acl, AdbAclField.USER)))
        group = self.blob_to_text(self.read_blob(self.obj_get(acl, AdbAclField.GROUP)))
        xattrs = self._parse_xattrs(self.obj_get(acl, AdbAclField.XATTRS))
        return (default_mode if mode is None else int(mode)), user, group, xattrs

    @staticmethod
    def _parse_target_blob(target: Optional[bytes]) -> tuple[FileKind, Optional[str], Optional[int]]:
        if not target:
            return FileKind.FILE, None, None
        if len(target) < 2:
            panic("Invalid target blob too short", FormatError)
        tmode = int.from_bytes(target[0:2], "little")
        payload = target[2:]
        ftype = stat.S_IFMT(tmode)
        match ftype:
            case stat.S_IFLNK:
                fkind = FileKind.SYMLINK
                dev = False
            case stat.S_IFREG:
                fkind = FileKind.HARDLINK
                dev = False
            case stat.S_IFBLK:
                fkind = FileKind.BLOCK
                dev = True
            case stat.S_IFCHR:
                fkind = FileKind.CHAR
                dev = True
            case stat.S_IFIFO:
                fkind = FileKind.FIFO
                dev = True
            case _:
                panic(f"Unsupported ftype {ftype} in TARGET", FormatError)
        if dev:
            if len(payload) != 8:
                panic("Invalid device/fifo target blob length", FormatError)
            return fkind, None, int.from_bytes(payload, "little")
        else:
            return fkind, payload.decode("utf-8"), None

    def parse_package(self) -> tuple[PackageMetadata, list[DirectoryEntry], list[FileEntry], dict[tuple[int, int], FileEntry]]:
        if len(self.adb) < SZ_CADB_HDR:
            panic("ADB payload too small for header", FormatError)
        hdr = CAdbHdr.from_buffer(self.adb)
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
            dmode, duser, dgroup, dxattrs = self._parse_acl(self.obj_get(path, AdbDirField.ACL), 0o755)
            dirs.append(DirectoryEntry(
                path=path_name,
                mode=dmode,
                user=duser,
                group=dgroup,
                path_idx=path_idx,
                xattrs=dxattrs,
            ))
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
                fmode, fuser, fgroup, fxattrs = self._parse_acl(self.obj_get(file_obj, AdbFileField.ACL), 0o644)
                fsize = self.read_int(self.obj_get(file_obj, AdbFileField.SIZE))
                fmtime = self.read_int(self.obj_get(file_obj, AdbFileField.MTIME))
                fhash_alg, fhash_hex = self._parse_hash(self.read_blob(self.obj_get(file_obj, AdbFileField.HASHES)))
                target_blob = self.read_blob(self.obj_get(file_obj, AdbFileField.TARGET))
                fkind, flink, fdev = self._parse_target_blob(target_blob)
                info = FileEntry(
                    path=full,
                    name=file_name,
                    path_idx=path_idx,
                    file_idx=file_idx,
                    kind=fkind,
                    size=0 if fsize is None else int(fsize),
                    mtime=0 if fmtime is None else int(fmtime),
                    mode=fmode,
                    user=fuser,
                    group=fgroup,
                    link_target=flink,
                    device=fdev,
                    xattrs=fxattrs,
                    hash_alg=fhash_alg,
                    hash_hex=fhash_hex,
                )
                file_entries.append(info)
                file_lookup[(path_idx, file_idx)] = info
        return metadata, dirs, file_entries, file_lookup

class _TarDataStream:
    def __init__(self, stream: AdbStream, size: int):
        self._stream = stream
        self._remaining = size

    def read(self, size: int = -1) -> bytes:
        if self._remaining <= 0:
            return b""
        if size < 0 or size > self._remaining:
            size = self._remaining
        data = self._stream.read_exact(size, "DATA payload")
        self._remaining -= len(data)
        return bytes(data)

class TarEmitter:
    NOBODY_ID = 65534
    USER_TO_UID = {
        "root": 0,
        "nobody": 65534,
    }
    GROUP_TO_GID = {
        "root": 0,
        "nobody": 65534,
        "nogroup": 65534,
    }

    def __init__(self, tar: tarfile.TarFile):
        self.tar = tar
        self.seen_dirs: set[str] = set()

    @staticmethod
    def _safe_pax_component(name: str) -> str:
        if all(0x20 <= ord(ch) <= 0x7E and ch not in "=\n" for ch in name):
            return name
        return f"hex:{name.encode('utf-8', errors='replace').hex()}"

    @staticmethod
    def _tarinfo_base(
        name: str,
        mode: int,
        mtime: int,
        user: Optional[str] = None,
        group: Optional[str] = None,
        uid: int = 0,
        gid: int = 0,
        pax_headers: Optional[dict[str, str]] = None,
    ) -> tarfile.TarInfo:
        ti = tarfile.TarInfo(name=name)
        ti.mode = mode & 0o7777
        ti.mtime = int(mtime)
        ti.uid = int(uid)
        ti.gid = int(gid)
        if user:
            ti.uname = user
        if group:
            ti.gname = group
        if pax_headers:
            ti.pax_headers = pax_headers
        return ti

    @classmethod
    def _resolve_uid(cls, user: Optional[str]) -> int:
        return cls.USER_TO_UID.get(user, 0) if user else 0

    @classmethod
    def _resolve_gid(cls, group: Optional[str]) -> int:
        return cls.GROUP_TO_GID.get(group, 0) if group else 0

    @classmethod
    def _build_pax_headers(
        cls,
        xattrs: list[XattrEntry],
        hash_alg: Optional[str] = None,
        hash_hex: Optional[str] = None,
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for x in xattrs:
            key = cls._safe_pax_component(x.name)
            headers[f"SCHILY.xattr.{key}"] = x.value_text if x.value_text is not None else f"hex:{x.value_hex}"
        if hash_hex and hash_alg:
            headers[f"APK-TOOLS.checksum.{hash_alg}"] = hash_hex
        return headers

    @classmethod
    def _tarinfo_file(cls, f: FileEntry, pax_headers: dict[str, str]) -> tarfile.TarInfo:
        return cls._tarinfo_base(
            f.path,
            f.mode,
            f.mtime,
            user=f.user,
            group=f.group,
            uid=cls._resolve_uid(f.user),
            gid=cls._resolve_gid(f.group),
            pax_headers=pax_headers,
        )

    def _add_parent_dirs(self, path: str):
        parts = Path(path).parts[:-1]
        current = ""
        for part in parts:
            current = f"{current}/{part}" if current else part
            if current in self.seen_dirs:
                continue
            ti = self._tarinfo_base(f"{current}/", 0o755, 0, user="root", group="root", uid=0, gid=0)
            ti.type = tarfile.DIRTYPE
            ti.size = 0
            self.tar.addfile(ti)
            self.seen_dirs.add(current)

    def add_dir(self, d: DirectoryEntry):
        path = d.path
        if not path or path in self.seen_dirs:
            return
        self._add_parent_dirs(path)
        ti = self._tarinfo_base(
            f"{path}/",
            d.mode,
            0,
            user=d.user,
            group=d.group,
            uid=self._resolve_uid(d.user),
            gid=self._resolve_gid(d.group),
            pax_headers=self._build_pax_headers(d.xattrs),
        )
        ti.type = tarfile.DIRTYPE
        ti.size = 0
        self.tar.addfile(ti)
        self.seen_dirs.add(path)

    def add_nondata_file(self, f: FileEntry):
        kind = f.kind
        path = f.path
        pax_headers = self._build_pax_headers(
            f.xattrs,
            hash_alg=f.hash_alg,
            hash_hex=f.hash_hex,
        )
        self._add_parent_dirs(path)
        match kind:
            case FileKind.FILE:
                if f.size == 0:
                    ti = self._tarinfo_file(f, pax_headers)
                    ti.size = 0
                    self.tar.addfile(ti, io.BytesIO())
            case FileKind.SYMLINK:
                ti = self._tarinfo_file(f, pax_headers)
                ti.type = tarfile.SYMTYPE
                ti.linkname = f.link_target or ""
                ti.size = 0
                self.tar.addfile(ti)
            case FileKind.HARDLINK:
                ti = self._tarinfo_file(f, pax_headers)
                ti.type = tarfile.LNKTYPE
                ti.linkname = f.link_target or ""
                ti.size = 0
                self.tar.addfile(ti)
            case FileKind.BLOCK:
                if f.device is None:
                    panic(f"BLOCK file missing device number: '{path}'", FormatError)
                ti = self._tarinfo_file(f, pax_headers)
                ti.type = tarfile.BLKTYPE
                ti.devmajor = os.major(f.device)
                ti.devminor = os.minor(f.device)
                ti.size = 0
                self.tar.addfile(ti)
            case FileKind.CHAR:
                if f.device is None:
                    panic(f"CHAR file missing device number: '{path}'", FormatError)
                ti = self._tarinfo_file(f, pax_headers)
                ti.type = tarfile.CHRTYPE
                ti.devmajor = os.major(f.device)
                ti.devminor = os.minor(f.device)
                ti.size = 0
                self.tar.addfile(ti)
            case FileKind.FIFO:
                ti = self._tarinfo_file(f, pax_headers)
                ti.type = tarfile.FIFOTYPE
                ti.size = 0
                self.tar.addfile(ti)
            case _:
                panic(f"Invalid file type to add: {kind}", FormatError)

    def add_data_file_stream(self, f: FileEntry, data_len: int, stream: AdbStream):
        self._add_parent_dirs(f.path)
        ti = self._tarinfo_file(
            f,
            self._build_pax_headers(
                f.xattrs,
                hash_alg=f.hash_alg,
                hash_hex=f.hash_hex,
            ),
        )
        ti.size = data_len
        self.tar.addfile(ti, _TarDataStream(stream, data_len))

@dataclass(frozen=True)
class BlockDesc:
    block_type: int
    raw_size: int
    payload_size: int

class ApkDumper:
    def __init__(self, stream: AdbStream, tar: tarfile.TarFile, meta_schemas: list[PackageSchemaMeta]):
        self.stream = stream
        self.tar_writer = TarEmitter(tar)
        self.meta_schemas = meta_schemas
        self._blk_index = 0
        self._file_lookup: dict[tuple[int, int], FileEntry] = {}
        self._written_data: set[tuple[int, int]] = set()

    def _read_block_desc(self) -> Optional[BlockDesc]:
        type_size_raw = self.stream.read_exact_or_none(SZ_CU32, "block type/size")
        if type_size_raw is None:
            return None

        type_size = Cu32.from_buffer(type_size_raw).value
        block_type = type_size >> 30
        if block_type == AdbBlockType.EXT:
            ext = self.stream.read_exact(SZ_CADB_BLOCK - SZ_CU32, "extended block header")
            blk = CAdbBlock.from_buffer(type_size_raw + ext)
            block_type = type_size & 0x3fffffff
            raw_size = blk.x_size
            hdr_size = SZ_CADB_BLOCK
        else:
            raw_size = type_size & 0x3fffffff
            hdr_size = SZ_CU32

        if raw_size < hdr_size:
            panic(f"Invalid block raw size {raw_size}", FormatError)
        return BlockDesc(block_type=block_type, raw_size=raw_size, payload_size=raw_size - hdr_size)

    def _read_first_adb_block_desc(self) -> BlockDesc:
        self._blk_index = 0
        blk = self._read_block_desc()
        if blk is None:
            panic("ADB stream did not contain an ADB block", FormatError)
        if blk.block_type != AdbBlockType.ADB:
            if blk.block_type == AdbBlockType.SIG:
                panic("Invalid block order: SIG block position", FormatError)
            if blk.block_type == AdbBlockType.DATA:
                panic("Invalid block order: DATA before ADB", FormatError)
            panic(f"Unknown block type {blk.block_type}", FormatError)
        return blk

    def _read_next_block_desc(self, last_raw_size: int) -> Optional[BlockDesc]:
        pad_remainder = last_raw_size & 0x7
        if pad_remainder:
            self.stream.skip(8 - pad_remainder, "block padding")
        blk = self._read_block_desc()
        if blk is not None:
            self._blk_index += 1
        return blk

    def _handle_adb_block(self, schema: int, payload_size: int):
        if payload_size < SZ_CADB_HDR:
            panic("ADB block payload too small", FormatError)
        adb_payload = self.stream.read_exact(payload_size, "ADB block payload")
        adb_hdr = CAdbHdr.from_buffer(adb_payload)
        logger.info(
            f"  [{self._blk_index}] ADB payload={payload_size} compat={adb_hdr.adb_compat_ver} ver={adb_hdr.adb_ver}"
        )

        if schema != AdbSchema.PACKAGE:
            self._file_lookup = {}
            return

        metadata, dirs, files, file_lookup = AdbReader(adb_payload).parse_package()
        self._file_lookup = file_lookup
        self.meta_schemas.append(PackageSchemaMeta(
            metadata=metadata,
            dirs=dirs,
            files=files,
        ))
        if metadata:
            logger.info("    package metadata:")
            for key, value in metadata.items():
                logger.info(f"      {key}: {value}")
        else:
            logger.info("    package metadata: (none)")
        logger.info(f"    all file paths ({len(files)}):")
        for f in files:
            logger.info(f"      {f.path}")

        for d in dirs:
            self.tar_writer.add_dir(d)
        for f in files:
            self.tar_writer.add_nondata_file(f)

    def _handle_sig_block(self, payload_size: int):
        if payload_size < SZ_CADB_SIGN_HDR:
            panic("SIG block payload too small", FormatError)
        sig_payload = self.stream.read_exact(payload_size, "SIG block payload")
        sig = CAdbSignHdr.from_buffer(sig_payload)
        logger.info(
            f"  [{self._blk_index}] SIG payload={payload_size} sign_v={sig.sign_ver} hash_alg={sig.hash_alg}"
        )

    def _handle_data_block(self, payload_size: int):
        if payload_size < SZ_CADB_DATA_PACKAGE:
            panic("Package DATA block payload too small", FormatError)
        data_hdr = self.stream.read_exact(SZ_CADB_DATA_PACKAGE, "DATA block package header")
        hdr = CAdbDataPackage.from_buffer(data_hdr)
        data_len = payload_size - SZ_CADB_DATA_PACKAGE
        file_info = self._file_lookup.get((hdr.path_idx, hdr.file_idx))
        logger.info(
            f"  [{self._blk_index}] DATA path_idx={hdr.path_idx} file_idx={hdr.file_idx} data_len={data_len}"
        )
        if file_info is None:
            panic(f"Unexpected DATA block for path_idx={hdr.path_idx} file_idx={hdr.file_idx}", FormatError)
        logger.info(f"      path={file_info.path}")

        key = (hdr.path_idx, hdr.file_idx)
        if key in self._written_data:
            panic(f"Duplicate DATA block for path_idx={hdr.path_idx} file_idx={hdr.file_idx}", FormatError)
        self._written_data.add(key)

        if file_info.kind != FileKind.FILE:
            panic(f"DATA block points to non-regular file '{file_info.path}'", FormatError)
        if data_len != file_info.size:
            panic(
                f"DATA size mismatch for '{file_info.path}': {data_len} != {file_info.size}",
                FormatError,
            )
        self.tar_writer.add_data_file_stream(file_info, data_len, self.stream)

    def _handle_package(self):
        self._file_lookup = {}
        self._written_data = set()

        blk = self._read_first_adb_block_desc()
        self._handle_adb_block(AdbSchema.PACKAGE, blk.payload_size)

        blk = self._read_next_block_desc(blk.raw_size)
        while blk is not None and blk.block_type == AdbBlockType.SIG:
            self._handle_sig_block(blk.payload_size)
            blk = self._read_next_block_desc(blk.raw_size)

        while blk is not None and blk.block_type == AdbBlockType.DATA:
            self._handle_data_block(blk.payload_size)
            blk = self._read_next_block_desc(blk.raw_size)

        if blk is not None:
            if blk.block_type == AdbBlockType.ADB:
                panic("Invalid block order: ADB block after SIG/DATA", FormatError)
            if blk.block_type == AdbBlockType.SIG:
                panic("Invalid block order: SIG block position", FormatError)
            panic(f"Unknown block type {blk.block_type}", FormatError)

    def run(self):
        schema = CAdbSchema.from_buffer(
            self.stream.read_exact(SZ_CADB_SCHEMA, "schema")
        ).value

        match schema:
            case AdbSchema.PACKAGE:
                logger.info("Schema: package")
                self._handle_package()
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

        with tarfile.open(path_tar, mode_tar) as tar, (path_meta or Path("/dev/null")).open("w") as f_json: # type: ignore[arg-type]
            meta_schemas: list[PackageSchemaMeta] = []
            ApkDumper(stream, tar, meta_schemas).run()

            meta_doc: dict[str, str | list[dict[str, object]]] = {
                "apk": str(path_apk),
                "schemas": [asdict(schema) for schema in meta_schemas],
            }
            json.dump(meta_doc, f_json, indent=2, sort_keys=True)
            f_json.write("\n")

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
    parser.add_argument("--json", type=Path, help="Dump the info JSON into said file")
    args = parser.parse_args()

    logger.info(f"Dumping APK '{args.apk}'")
    dump(args.apk, args.tar, args.json)
