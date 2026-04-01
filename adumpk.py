#!/usr/bin/env python3
from abc import ABC, abstractmethod
import argparse
import base64
from contextlib import ExitStack
try:
    from compression import zstd
except ModuleNotFoundError:
    zstd = None
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
import io
import json
import logging
import os
from pathlib import PosixPath as Path
import stat
import sys
import tarfile
import time
from typing import Any, BinaryIO, Literal, NoReturn, Optional, Self, Sequence, Type, Union
import zlib

logger = logging.getLogger(__name__)

class AdbFormatError(ValueError):
    pass

def panic(msg: str, etype: Type[Exception] = ValueError) -> NoReturn:
    logger.fatal(msg)
    raise etype(msg)

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

class AdbAclField(AdbField):
    MODE   = 1
    USER   = 2
    GROUP  = 3
    XATTRS = 4

class AdbDepField(AdbField):
    NAME    = 1
    VERSION = 2
    MATCH   = 3

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

class AdbIndexField(AdbField):
    DESCRIPTION	    = 1
    PACKAGES	    = 2
    PKGNAME_SPEC    = 3

class AdbPkgField(AdbField):
    PKGINFO  = 1
    PATHS    = 2
    SCRIPTS  = 3
    TRIGGERS = 4

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

class AdbScriptField(AdbField):
    TRIGGER     = 1
    PREINST     = 2
    POSTINST    = 3
    PREDEINST   = 4
    POSTDEINST  = 5
    PREUPGRADE  = 6
    POSTUPGRADE = 7

@dataclass
class ApkDepend:
    name: str = ""
    version: str = ""
    # field for match:
    # EQUAL    = 0b00001 # 1 << 0
    # LESS     = 0b00010 # 1 << 1
    # GREATER  = 0b00100 # 1 << 2
    # FUZZY    = 0b01000 # 1 << 3
    # CONFLICT = 0b10000 # 1 << 4

    match: int = 0b0001

    def literal(self) -> str:
        if self.version:
            if self.match & 0b10000:
                flags = self.match & 0b01111
                conflict = "!"
            else:
                flags = self.match
                conflict = ""
            match flags:
                case 0b0010:
                    sign = "<"
                case 0b0011:
                    sign = "<="
                case 0b1011:
                    sign = "<~"
                case 0b1001:
                    sign = "~"
                case 0b0001:
                    sign = "="
                case 0b0101:
                    sign = ">="
                case 0b1101:
                    sign = ">~"
                case 0b0100:
                    sign = ">"
                case _:
                    panic(f"Invalid dep flags 0b{flags:b}")
            return f"{conflict}{self.name}{sign}{self.version}"
        else:
            return self.name

class ApkHashType(IntEnum):
    NONE        = 0
    SHA1        = 2
    SHA256      = 3
    SHA512      = 4
    SHA256_160  = 5

    def __str__(self):
        return (
            "none",
            "INVALID",
            "sha1",
            "sha256",
            "sha512",
            "sha256_160"
        )[self]

@dataclass
class ApkHash:
    hash_type: ApkHashType = ApkHashType.NONE
    raw: bytes = b""
    as_hex: str = ""

    @classmethod
    def from_raw(cls, raw: bytes | bytearray) -> Self:
        len_hash = len(raw)
        match len_hash:
            case 20:
                hash_type = ApkHashType.SHA1
            case 32:
                hash_type = ApkHashType.SHA256
            case 64:
                hash_type = ApkHashType.SHA512
            case _:
                panic(f"Unknown hash with length {len_hash}", AdbFormatError)
        return cls(hash_type, bytes(raw), raw.hex())

    def as_json_dict(self) -> dict[str, str]:
        return {
            "type": str(self.hash_type),
            "value": self.as_hex
        }

def _str_from_optional_int(value: Optional[int]):
    if value is None:
        return ""
    else:
        return str(value)

@dataclass
class AdbPkginfo:
    name: str = ""
    version: str = ""
    hashes: ApkHash = field(default_factory=ApkHash)
    description: str = ""
    arch: str = ""
    license: str = ""
    origin: str = ""
    maintainer: str = ""
    url: str = ""
    repo_commit: bytes = b""
    build_time: Optional[int] = None
    installed_size: Optional[int] = None
    file_size: Optional[int] = None
    provider_priority: Optional[int] = None
    depends: list[ApkDepend] = field(default_factory=list)
    provides: list[ApkDepend] = field(default_factory=list)
    replaces: list[ApkDepend] = field(default_factory=list)
    install_if: list[ApkDepend] = field(default_factory=list)
    recommends: list[ApkDepend] = field(default_factory=list)
    layer: Optional[int] = None
    tags: list[str] = field(default_factory=list)

    def show(self):
        values = [
            ("name", self.name),
            ("version", self.version),
            ("checksum", "-"),
            ("description", self.description),
            ("arch", self.arch),
            ("license", self.license),
            ("origin", self.origin),
            ("maintainer", self.maintainer),
            ("url", self.url),
            ("repo-commit", self.repo_commit.hex()),
            ("build-time", _str_from_optional_int(self.build_time)),
            ("installed-size", _str_from_optional_int(self.installed_size)),
            ("file-size", _str_from_optional_int(self.file_size)),
            ("provider-priority", _str_from_optional_int(self.provider_priority)),
            ("depends", [item.literal() for item in self.depends]),
            ("provides", [item.literal() for item in self.provides]),
            ("replaces", [item.literal() for item in self.replaces]),
            ("install-if", [item.literal() for item in self.install_if]),
            ("recommends", [item.literal() for item in self.recommends]),
            ("layer", _str_from_optional_int(self.layer)),
            ("tags", self.tags),
        ]
        if self.hashes is not None:
            values[2] = (str(self.hashes.hash_type) + "sum", self.hashes.as_hex)
        for key, value in values:
            logger.info(f"{key:17}: {value}")

    def as_json_dict(self) -> dict[str, Union[str, dict[str, str], list[str]]]:
        return {
            "name": self.name,
            "version": self.version,
            "checksum": self.hashes.as_json_dict(),
            "description": self.description,
            "arch": self.arch,
            "license": self.license,
            "origin": self.origin,
            "maintainer": self.maintainer,
            "url": self.url,
            "repo-commit": self.repo_commit.hex(),
            "build-time": _str_from_optional_int(self.build_time),
            "installed-size": _str_from_optional_int(self.installed_size),
            "file-size": _str_from_optional_int(self.file_size),
            "provider-priority": _str_from_optional_int(self.provider_priority),
            "depends": [item.literal() for item in self.depends],
            "provides": [item.literal() for item in self.provides],
            "replaces": [item.literal() for item in self.replaces],
            "install-if": [item.literal() for item in self.install_if],
            "recommends": [item.literal() for item in self.recommends],
            "layer": _str_from_optional_int(self.layer),
            "tags": self.tags,
        }

def _str_b64_from_bytes(value: bytes | bytearray) -> str:
    if value:
        return base64.b64encode(value).decode("ascii")
    else:
        return ""

@dataclass
class ApkAcl:
    mode: int = 0
    user: str = ""
    group: str = ""
    xattrs: list[tuple[str, bytes]] = field(default_factory=list)

    def literal(self):
        parts = []
        for mode in (self.mode & 0o700) >> 6, (self.mode & 0o070) >> 3, self.mode & 0o007:
            if mode & 0o4:
                parts.append("r")
            else:
                parts.append("-")
            if mode & 0o2:
                parts.append("w")
            else:
                parts.append("-")
            if mode & 0o1:
                parts.append("x")
            else:
                parts.append("-")
        return f"{''.join(parts)} {len(self.xattrs)} {self.user} {self.group}"

    def as_json_dict(self) -> dict[str, Union[str, list[dict[str, str]]]]:
        return {
            "mode": oct(self.mode),
            "user": self.user,
            "group": self.group,
            "xattrs": [{"key": xattr[0], "value": _str_b64_from_bytes(xattr[1])} for xattr in self.xattrs]
        }

class ApkFileKind(StrEnum):
    REGULAR = "regular"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    BLOCK = "block"
    CHAR = "char"
    FIFO = "fifo"

@dataclass
class ApkDev:
    major: int
    minor: int

    @classmethod
    def from_raw(cls, value: int) -> Self:
        return cls(os.major(value), os.minor(value))

    def as_json_dict(self) -> dict[str, str]:
        return {
            "major": str(self.major),
            "minor": str(self.minor),
        }

@dataclass
class ApkFile:
    name: str = ""
    acl: ApkAcl = field(default_factory=ApkAcl)
    size: Optional[int] = None
    mtime: Optional[int] = None
    hashes: ApkHash = field(default_factory=ApkHash)
    target: str = ""
    kind: ApkFileKind = ApkFileKind.REGULAR
    dev: Optional[ApkDev] = None

    def as_json_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "acl": self.acl.as_json_dict(),
            "size": _str_from_optional_int(self.size),
            "mtime": _str_from_optional_int(self.mtime),
            "hashes": self.hashes.as_json_dict(),
            "target": self.target,
            "kind": str(self.kind),
            "dev": {} if self.dev is None else self.dev.as_json_dict()
        }

@dataclass
class ApkDir:
    name: str = ""
    acl: ApkAcl = field(default_factory=ApkAcl)
    files: list[ApkFile] = field(default_factory=list)

    def as_json_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "acl": self.acl.as_json_dict(),
            "files": [file.as_json_dict() for file in self.files]
        }

@dataclass
class ApkPaths:
    dirs: list[ApkDir] = field(default_factory=list)

    def show(self):
        logger.info("Paths:")
        for id_directory, directory in enumerate(self.dirs, 1):
            logger.info(f"{id_directory:3},    d{directory.acl.literal()}                                        {directory.name}/")
            for id_file, file in enumerate(directory.files, 1):
                target = ""
                match file.kind:
                    case ApkFileKind.REGULAR:
                        char_type = "-"
                        file_size = f"{file.size:13}"
                    case ApkFileKind.SYMLINK:
                        char_type = "l"
                        target = f" -> {file.target}"
                        file_size = " " * 13
                    case ApkFileKind.HARDLINK:
                        char_type = "-"
                        target = f" -> {file.target}"
                        file_size = " " * 13
                    case ApkFileKind.BLOCK:
                        char_type = "b"
                        if file.dev is None:
                            panic("Empty dev number for block device")
                        file_size = f"{file.dev.major:6},{file.dev.minor:6}"
                    case ApkFileKind.CHAR:
                        char_type = "c"
                        if file.dev is None:
                            panic("Empty dev number for char device")
                        file_size = f"{file.dev.major:6},{file.dev.minor:6}"
                    case ApkFileKind.FIFO:
                        char_type = "p"
                        if file.dev is None:
                            panic("Empty dev number for fifo device")
                        file_size = f"{file.dev.major:6},{file.dev.minor:6}"
                    case _:
                        panic(f"Invalid File kind {file.kind}")
                logger.info(f"{id_directory:3},{id_file:3} {char_type}{file.acl.literal()} {file_size} {time.ctime(file.mtime)} {directory.name}/{file.name}{target}")

@dataclass
class ApkScripts:
    trigger: bytes = b""
    preinst: bytes = b""
    postinst: bytes = b""
    predeinst: bytes = b""
    postdeinst: bytes = b""
    preupgrade: bytes = b""
    postupgrade: bytes = b""

    def show(self):
        lines = []
        for key in ("trigger", "preinst", "postinst", "predeinst", "postdeinst", "preupgrade", "postupgrade"):
            attr = getattr(self, key)
            if attr:
                len_attr = len(attr)
                if len_attr > 50:
                    peek = f"{attr[:25]} ... {attr[-25:]}"
                else:
                    peek = f"{attr}"
                lines.append(f"{key} ({peek}) len={len_attr}")
        logger.info(f"Scripts ({len(lines)}):")
        for line in lines:
            logger.info(line)

    def as_json_dict(self) -> dict[str, str]:
        return {
            "trigger": _str_b64_from_bytes(self.trigger),
            "pre-install": _str_b64_from_bytes(self.preinst),
            "post-install": _str_b64_from_bytes(self.postinst),
            "pre-deinstall": _str_b64_from_bytes(self.predeinst),
            "post-deinstall": _str_b64_from_bytes(self.postdeinst),
            "pre-upgrade": _str_b64_from_bytes(self.preupgrade),
            "post-upgrade": _str_b64_from_bytes(self.postupgrade),
        }

@dataclass
class ApkTriggers:
    paths: list[str] = field(default_factory=list)

    def show(self):
        logger.info(f"Triggers ({len(self.paths)}):")
        for path in self.paths:
            logger.info(path)

@dataclass
class ApkMetainfo:
    pkginfo: AdbPkginfo
    paths: ApkPaths
    scripts: ApkScripts
    triggers: ApkTriggers

    def as_json_dict(self) -> dict[str, Any]:
        return {
            "pkginfo": self.pkginfo.as_json_dict(),
            "paths": [d.as_json_dict() for d in self.paths.dirs],
            "scripts": self.scripts.as_json_dict(),
            "triggers": self.triggers.paths
        }

@dataclass
class AdbIndexPackages:
    packages: list[AdbPkginfo] = field(default_factory=list)

    def show(self):
        logger.info(f"Packages ({len(self.packages)}):")
        line = "=" * 80
        logger.info(line)
        for package in self.packages:
            package.show()
            logger.info(line)

@dataclass
class AdbIndex:
    packages: AdbIndexPackages

    def as_json_dict(self) -> dict[str, Any]:
        return {
            "packages": {package.name: package.as_json_dict() for package in self.packages.packages}
        }

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
                panic(f"Truncated {what}", AdbFormatError)
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
                panic(f"Truncated {what}", AdbFormatError)
            remaining -= len(chunk)

    def lossy_assert_raw(self):
        header = self.read_exact(4, "raw header")
        if header != b"ADB.":
            panic(f"Inner raw stream is not b'ADB.' (BE 0x6164622E), but BE 0x{header[0]:x}{header[1]:x}{header[2]:x}{header[3]:x}", AdbFormatError)

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
            out.extend(self._buffer[0:len_out-size_first])
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

class ZstandardAdbStream(AdbStream):
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
                    panic("Truncated zstd stream", AdbFormatError)
            else:
                in_chunk = b""

            out_chunk = self._decompressor.decompress(in_chunk)
            if out_chunk:
                self._buffer.write(out_chunk)
            elif self._decompressor.needs_input and not in_chunk:
                panic("Truncated zstd stream", AdbFormatError)

            if self._decompressor.eof:
                self._eof = True
                break

    def read(self, size: int) -> bytearray:
        if size <= 0:
            return bytearray()
        self._fill(size)
        return self._buffer.read(size)

@dataclass(frozen=True)
class AdbVal:
    __slots__ = ("vtype", "value")

    vtype: AdbValType
    value: int

    @classmethod
    def from_int(cls, u32: int) -> Self:
        return cls(AdbValType(u32 & 0xF0000000), u32 & 0x0FFFFFFF)

    @classmethod
    def must_init(cls, u32: int) -> Self:
        if u32 == 0:
            raise ValueError("Initializing AdbVal with 0")
        return cls.from_int(u32)

    @classmethod
    def maybe_init(cls, u32: int) -> Optional[Self]:
        if u32 == 0:
            return None
        return cls.from_int(u32)

    @classmethod
    def in_values(cls, values: Sequence[Optional[Self]], index: AdbField) -> Optional[Self]:
        if index > 0 and index <= len(values):
            return values[index - 1]
        return None

def _uint_from(data: bytes | bytearray) -> int:
    return int.from_bytes(data, "little", signed=False)

class AdbBlockAdbReader:
    __slots__ = ("data",)

    def __init__(self, data: bytearray):
        self.data = data

    def u8_at(self, offset: int) -> int:
        return _uint_from(self.data[offset:offset+1])

    def u16_at(self, offset: int) -> int:
        return _uint_from(self.data[offset:offset+2])

    def u32_at(self, offset: int) -> int:
        return _uint_from(self.data[offset:offset+4])

    def u64_at(self, offset: int) -> int:
        return _uint_from(self.data[offset:offset+8])

    def read_uint(self, header: AdbVal) -> int:
        match header.vtype:
            case AdbValType.INT:
                return header.value
            case AdbValType.INT32:
                return self.u32_at(header.value)
            case AdbValType.INT64:
                return self.u64_at(header.value)
            case _:
                panic(f"Reading a non INT (type {header.vtype}) for BLOB")

    def read_blob(self, header: AdbVal) -> bytearray:
        match header.vtype:
            case AdbValType.BLOB8:
                count = self.u8_at(header.value)
                skip = 1
            case AdbValType.BLOB16:
                count = self.u16_at(header.value)
                skip = 2
            case AdbValType.BLOB32:
                count = self.u32_at(header.value)
                skip = 4
            case _:
                panic(f"Reading a non BLOB (type {header.vtype}) for BLOB")
        if count == 0:
            return bytearray()
        offset = header.value + skip
        return self.data[offset:offset+count]

    def read_bytes(self, header: AdbVal) -> bytes:
        return bytes(self.read_blob(header))

    def read_text(self, header: AdbVal) -> str:
        return self.read_blob(header).decode("utf-8")

    def read_values(self, header: AdbVal) -> list[Optional[AdbVal]]:
        if header.vtype != AdbValType.ARRAY and header.vtype != AdbValType.OBJECT:
            panic(f"Expected object/array value, got type {header.vtype:#x}", AdbFormatError)
        count = self.u32_at(header.value)
        return [AdbVal.maybe_init(self.u32_at(header.value + i * 4)) for i in range(1, count)]

    def read_depend(self, header: AdbVal) -> ApkDepend:
        depend = ApkDepend()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbDepField(id_value)
            match id_field:
                case AdbDepField.NAME:
                    depend.name = self.read_text(value)
                case AdbDepField.VERSION:
                    depend.version = self.read_text(value)
                case AdbDepField.MATCH:
                    depend.match = self.read_uint(value)
                case _:
                    panic(f"Unexpected field {id_field} in depend")
        return depend

    def read_depends(self, header: AdbVal) -> list[ApkDepend]:
        return [self.read_depend(value) for value in self.read_values(header) if value is not None]

    def read_pkginfo(self, header: AdbVal) -> AdbPkginfo:
        info = AdbPkginfo()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbPkgInfoField(id_value)
            match id_field:
                case AdbPkgInfoField.NAME:
                    info.name = self.read_text(value)
                case AdbPkgInfoField.VERSION:
                    info.version = self.read_text(value)
                case AdbPkgInfoField.HASHES:
                    info.hashes = ApkHash.from_raw(self.read_blob(value))
                case AdbPkgInfoField.DESCRIPTION:
                    info.description = self.read_text(value)
                case AdbPkgInfoField.ARCH:
                    info.arch = self.read_text(value)
                case AdbPkgInfoField.LICENSE:
                    info.license = self.read_text(value)
                case AdbPkgInfoField.ORIGIN:
                    info.origin = self.read_text(value)
                case AdbPkgInfoField.MAINTAINER:
                    info.maintainer = self.read_text(value)
                case AdbPkgInfoField.URL:
                    info.url = self.read_text(value)
                case AdbPkgInfoField.REPO_COMMIT:
                    info.repo_commit = self.read_bytes(value)
                case AdbPkgInfoField.BUILD_TIME:
                    info.build_time = self.read_uint(value)
                case AdbPkgInfoField.INSTALLED_SIZE:
                    info.installed_size = self.read_uint(value)
                case AdbPkgInfoField.FILE_SIZE:
                    info.file_size = self.read_uint(value)
                case AdbPkgInfoField.PROVIDER_PRIORITY:
                    info.provider_priority = self.read_uint(value)
                case AdbPkgInfoField.DEPENDS:
                    info.depends = self.read_depends(value)
                case AdbPkgInfoField.PROVIDES:
                    info.provides = self.read_depends(value)
                case AdbPkgInfoField.REPLACES:
                    info.replaces = self.read_depends(value)
                case AdbPkgInfoField.INSTALL_IF:
                    info.install_if = self.read_depends(value)
                case AdbPkgInfoField.RECOMMENDS:
                    info.recommends = self.read_depends(value)
                case AdbPkgInfoField.LAYER:
                    info.layer = self.read_uint(value)
                case AdbPkgInfoField.TAGS:
                    info.tags = ["" if sub_value is None else self.read_text(sub_value) for sub_value in self.read_values(value)]
                case _:
                    panic(f"Unexpected field {id_field} in pkginfo")
        return info

    def read_acl(self, header: AdbVal) -> ApkAcl:
        acl = ApkAcl()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbAclField(id_value)
            match id_field:
                case AdbAclField.MODE:
                    acl.mode = self.read_uint(value)
                case AdbAclField.USER:
                    acl.user = self.read_text(value)
                case AdbAclField.GROUP:
                    acl.group = self.read_text(value)
                case AdbAclField.XATTRS:
                    for id_sub, sub_value in enumerate(self.read_values(value), 1):
                        if sub_value is None:
                            panic(f"Empty XATTR entry (ID {id_sub}) not allowed", AdbFormatError)
                        if sub_value.vtype != AdbValType.BLOB8:
                            panic(f"XATTR entry is not BLOB8 but {sub_value.vtype}", AdbFormatError)
                        parts = self.read_blob(sub_value).split(b"\x00", 1)
                        if len(parts) != 2:
                            panic(f"XATTR entry does not have NULL byte as sep")
                        acl.xattrs.append((parts[0].decode(), bytes(parts[1])))
        return acl

    def read_file(self, header: AdbVal) -> ApkFile:
        file = ApkFile()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbFileField(id_value)
            match id_field:
                case AdbFileField.NAME:
                    file.name = self.read_text(value)
                case AdbFileField.ACL:
                    file.acl = self.read_acl(value)
                case AdbFileField.SIZE:
                    file.size = self.read_uint(value)
                case AdbFileField.MTIME:
                    file.mtime = self.read_uint(value)
                case AdbFileField.HASHES:
                    file.hashes = ApkHash.from_raw(self.read_blob(value))
                case AdbFileField.TARGET:
                    target = self.read_blob(value)
                    file_ifmt = stat.S_IFMT(_uint_from(target[0:2]))
                    match file_ifmt:
                        case stat.S_IFLNK:
                            file.kind = ApkFileKind.SYMLINK
                            is_dev = False
                        case stat.S_IFREG:
                            file.kind = ApkFileKind.HARDLINK
                            is_dev = False
                        case stat.S_IFBLK:
                            file.kind = ApkFileKind.BLOCK
                            is_dev = True
                        case stat.S_IFCHR:
                            file.kind = ApkFileKind.CHAR
                            is_dev = True
                        case stat.S_IFIFO:
                            file.kind = ApkFileKind.FIFO
                            is_dev = True
                        case _:
                            panic(f"Invalid file type {file_ifmt:x} for special file {file.name}", AdbFormatError)
                    if is_dev:
                        if len(target) != 10:
                            panic(f"Invalid device/fifo target blob length for special file {file.name}", AdbFormatError)
                        file.dev = ApkDev.from_raw(_uint_from(target[2:10]))
                    else:
                        file.target = target[2:].decode("utf-8")
        return file

    def read_dir(self, header: AdbVal) -> ApkDir:
        directory = ApkDir()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbDirField(id_value)
            match id_field:
                case AdbDirField.NAME:
                    directory.name = self.read_text(value)
                case AdbDirField.ACL:
                    directory.acl = self.read_acl(value)
                case AdbDirField.FILES:
                    for id_sub, sub_value in enumerate(self.read_values(value), 1):
                        if sub_value is None:
                            panic(f"Empty FILE entry (ID {id_sub}) not allowed", AdbFormatError)
                        if sub_value.vtype != AdbValType.OBJECT:
                            panic(f"FILE entry is not OBJECT but {sub_value.vtype}", AdbFormatError)
                        directory.files.append(self.read_file(sub_value))
                case _:
                    panic(f"Unexpected field {id_field} in dir")
        return directory

    def read_paths(self, header: AdbVal) -> ApkPaths:
        paths = ApkPaths()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                panic(f"Empty PATHS entry (ID {id_value}) not allowed", AdbFormatError)
            if AdbValType.OBJECT != value.vtype:
                panic(f"ADB PATHS entry should be OBJECT, but it was {value.vtype} instead")
            paths.dirs.append(self.read_dir(value))
        return paths

    def read_scripts(self, header: AdbVal) -> ApkScripts:
        scripts = ApkScripts()
        for id_value, value in enumerate(self.read_values(header), 1):
            if value is None:
                continue
            id_field = AdbScriptField(id_value)
            match id_field:
                case AdbScriptField.TRIGGER:
                    scripts.trigger = self.read_bytes(value)
                case AdbScriptField.PREINST:
                    scripts.preinst = self.read_bytes(value)
                case AdbScriptField.POSTINST:
                    scripts.postinst = self.read_bytes(value)
                case AdbScriptField.PREDEINST:
                    scripts.predeinst = self.read_bytes(value)
                case AdbScriptField.POSTDEINST:
                    scripts.postdeinst = self.read_bytes(value)
                case AdbScriptField.PREUPGRADE:
                    scripts.preupgrade = self.read_bytes(value)
                case AdbScriptField.POSTUPGRADE:
                    scripts.postupgrade = self.read_bytes(value)
                case _:
                    panic(f"Unexpected field {id_field} in scripts")
        return scripts

    def read_triggers(self, header: AdbVal) -> ApkTriggers:
        return ApkTriggers(
            [self.read_text(value) for value in self.read_values(header) if value is not None]
        )

    def read_index_packages(self, header: AdbVal) -> AdbIndexPackages:
        return AdbIndexPackages(
            [self.read_pkginfo(value) for value in self.read_values(header) if value is not None]
        )

    def read_values_root(self) -> list[Optional[AdbVal]]:
        root = _uint_from(self.data[4:8])
        if root == 0:
            panic("ADB has a root field with 0, the whole package shall be omitted")

        value_root = AdbVal.from_int(root)
        if value_root.vtype != AdbValType.OBJECT:
            panic(f"ADB root is not OBJECT but {value_root.vtype}", AdbFormatError)

        return self.read_values(value_root)

    def parse_apk(self) -> ApkMetainfo:
        values = self.read_values_root()

        value = AdbVal.in_values(values, AdbPkgField.PKGINFO)
        if value is None:
            panic(f"ADB pkginfo does not exist, which is not allowed", AdbFormatError)
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB pkginfo is not OBJECT but {value.vtype}", AdbFormatError)
        pkginfo = self.read_pkginfo(value)
        pkginfo.show()

        value = AdbVal.in_values(values, AdbPkgField.PATHS)
        if value is None:
            paths = ApkPaths()
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB paths is not OBJECT but {value.vtype}", AdbFormatError)
        else:
            paths = self.read_paths(value)
            paths.show()

        value = AdbVal.in_values(values, AdbPkgField.SCRIPTS)
        if value is None:
            scripts = ApkScripts()
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB scripts is not OBJECT but {value.vtype}", AdbFormatError)
        else:
            scripts = self.read_scripts(value)
            scripts.show()

        value = AdbVal.in_values(values, AdbPkgField.TRIGGERS)
        if value is None:
            triggers = ApkTriggers()
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB triggers it not OBJECT but {value.vtype}", AdbFormatError)
        else:
            triggers = self.read_triggers(value)
            triggers.show()

        return ApkMetainfo(pkginfo, paths, scripts, triggers)

    def parse_index(self):
        values = self.read_values_root()

        value = AdbVal.in_values(values, AdbIndexField.DESCRIPTION)
        if value is None:
            pass
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB description is not OBJECT but {value.vtype}", AdbFormatError)
        else:
            pass

        value = AdbVal.in_values(values, AdbIndexField.PACKAGES)
        if value is None:
            packages = AdbIndexPackages()
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB packages is not OBJECT but {value.vtype}", AdbFormatError)
        else:
            packages = self.read_index_packages(value)
        packages.show()

        value = AdbVal.in_values(values, AdbIndexField.PKGNAME_SPEC)
        if value is None:
            pass
        elif value.vtype != AdbValType.OBJECT:
            panic(f"ADB pkgname spec is not OBJECT but {value.vtype}", AdbFormatError)
        else:
            pass

        return AdbIndex(packages)


@dataclass(frozen=True)
class AdbBlock:
    type_block: AdbBlockType
    size_raw: int
    size_payload: int

class AdbStreamSlice:
    def __init__(self, stream: AdbStream, size: int):
        self.stream = stream
        self.remain = size

    def read(self, size: int = -1) -> bytes:
        if self.remain <= 0:
            return b""
        if size < 0 or size > self.remain:
            size = self.remain
        data = self.stream.read_exact(size, "slice")
        self.remain -= len(data)
        return bytes(data)

class ApkRootTarWriter:
    def __init__(self, path_tar: Path, paths: ApkPaths, stream: AdbStream, checksum: bool):
        self.path_tar = path_tar
        mode_tar = "w"
        if "." in path_tar.name:
            match path_tar.name.rsplit(".", 1)[-1]:
                case "gz":
                    mode_tar += ":gz"
                case "bz2":
                    mode_tar += ":bz2"
                case "xz":
                    mode_tar += ":xz"
                case "zst":
                    mode_tar += ":zst"
        self.mode_tar: Literal["w", "w:gz", "w:bz2", "w:xz", "w:zst"] = mode_tar
        self.dirs = paths.dirs
        self.stream = stream
        self.checksum = checksum
        self.id_next_dir = 1
        self.id_next_file = 1

    def __enter__(self) -> Self:
        self.tar = tarfile.open(self.path_tar, self.mode_tar)
        # empty root dir not needed
        if self.dirs[0].name:
            panic(f"First directory name not empty but {self.dirs[0].name}", AdbFormatError)
        return self

    def __exit__(self, exc_type, exc, tb):
        count_dirs = len(self.dirs)
        if self.id_next_dir < count_dirs:
            self.fill(count_dirs, len(self.dirs[-1].files) + 1)
        elif self.id_next_dir == count_dirs:
            count_files = len(self.dirs[-1].files)
            if self.id_next_file <= count_files:
                self.fill(count_dirs, count_files + 1)
        self.tar.close()

    @staticmethod
    def update_info_from_acl(info: tarfile.TarInfo, acl: ApkAcl):
        info.mode = acl.mode
        info.uname = acl.user
        info.gname = acl.group
        match acl.user:
            case "root":
                info.uid = 0
            case "nobody":
                info.uid = 65534
        match acl.group:
            case "root":
                info.gid = 0
            case "nogroup":
                info.gid = 65534
        if acl.xattrs:
            pax_headers = {}
            for xattr_name, xattr_value in acl.xattrs:
                name_pax = []
                for byte in xattr_name.encode("utf-8"):
                    # Keep visible ASCII (0x21-0x7e) except '%' (0x25) and '=' (0x3d), which are escaped as %XX.
                    if 0x21 <= byte <= 0x7e and byte not in (0x25, 0x3d):
                        name_pax.append(chr(byte))
                    else:
                        name_pax.append(f"%{byte:02X}")
                # Preserve arbitrary xattr bytes losslessly through pax BINARY mode.
                value_pax = bytes(xattr_value).decode("utf-8", "surrogateescape")
                pax_headers[f"SCHILY.xattr.{''.join(name_pax)}"] = value_pax
            info.pax_headers = pax_headers

    def add_dir(self, directory: ApkDir):
        logger.debug(f"{self.path_tar} <d- {directory.name}/")
        info = tarfile.TarInfo(directory.name)
        info.type = tarfile.DIRTYPE
        self.update_info_from_acl(info, directory.acl)
        self.tar.addfile(info)

    @staticmethod
    def set_info_dev_number(info: tarfile.TarInfo, dev: Optional[ApkDev]):
        if dev is None:
            panic("Device without dev number")
        info.devmajor = dev.major
        info.devminor = dev.minor

    def add_file_empty(self, name_dir: str, file: ApkFile):
        name_file = f"{name_dir}/{file.name}"
        info = tarfile.TarInfo(name_file)
        info.size = file.size or 0
        info.mtime = file.mtime or 0
        self.update_info_from_acl(info, file.acl)
        match file.kind:
            case ApkFileKind.REGULAR:
                if file.size and file.size > 0:
                    panic(f"Adding a file with size {file.size} as empty file", AdbFormatError)
                info.type = tarfile.REGTYPE
                char_type = "f"
            case ApkFileKind.SYMLINK:
                info.linkname = file.target
                info.type = tarfile.SYMTYPE
                char_type = "l"
            case ApkFileKind.HARDLINK:
                info.linkname = file.target
                info.type = tarfile.LNKTYPE
                char_type = "L"
            case ApkFileKind.BLOCK:
                self.set_info_dev_number(info, file.dev)
                info.type = tarfile.BLKTYPE
                char_type = "b"
            case ApkFileKind.CHAR:
                self.set_info_dev_number(info, file.dev)
                info.type = tarfile.CHRTYPE
                char_type = "c"
            case ApkFileKind.FIFO:
                self.set_info_dev_number(info, file.dev)
                info.type = tarfile.FIFOTYPE
                char_type = "p"
            case _:
                panic(f"Invalid File kind {file.kind}")
        logger.debug(f"{self.path_tar} <{char_type}- {name_file}")
        self.tar.addfile(info)

    def add_file_data(self, name_dir: str, file: ApkFile):
        name_file = f"{name_dir}/{file.name}"
        logger.debug(f"{self.path_tar} <f- {name_file}")
        info = tarfile.TarInfo(name_file)
        if file.size is None:
            panic("Adding an supposedly empty file with data")
        info.size = file.size
        info.mtime = file.mtime or 0
        info.type = tarfile.REGTYPE
        self.update_info_from_acl(info, file.acl)
        if self.checksum and file.hashes.as_hex:
            pax_headers = dict(info.pax_headers)
            pax_headers[f"APK-TOOLS.checksum.{file.hashes.hash_type}"] = file.hashes.as_hex
            info.pax_headers = pax_headers
        self.tar.addfile(info, AdbStreamSlice(self.stream, file.size))

    def fill(self, id_until_dir: int, id_until_file: int):
        while self.id_next_dir < id_until_dir:
            directory = self.dirs[self.id_next_dir - 1]
            count_files = len(directory.files)
            while self.id_next_file <= count_files:
                file = directory.files[self.id_next_file - 1]
                self.add_file_empty(directory.name, file)
                self.id_next_file += 1
            self.add_dir(self.dirs[self.id_next_dir])
            self.id_next_dir += 1
            self.id_next_file = 1
        directory = self.dirs[id_until_dir - 1]
        while self.id_next_file < id_until_file:
            file = directory.files[self.id_next_file - 1]
            self.add_file_empty(directory.name, file)
            self.id_next_file += 1

    def add(self, id_dir: int, id_file: int, size: int):
        if id_dir > self.id_next_dir:
            self.fill(id_dir, id_file)
        elif id_dir == self.id_next_dir:
            if id_file > self.id_next_file:
                self.fill(id_dir, id_file)
            elif id_file < self.id_next_file:
                panic(f"Backwards in files, {id_file} < {self.id_next_file}", AdbFormatError)
        else:
            panic(f"Backwards in dirs, {id_dir} < {self.id_next_dir}", AdbFormatError)
        directory = self.dirs[id_dir - 1]
        file = directory.files[id_file - 1]
        if file.size != size:
            panic(f"Adding a file with mismatch recorded size {file.size} vs actual size {size}")
        self.add_file_data(directory.name, file)
        if id_file < len(directory.files):
            self.id_next_file = id_file + 1
        else:
            if id_dir < len(self.dirs):
                self.add_dir(self.dirs[id_dir]) # actually next
            self.id_next_dir += 1
            self.id_next_file = 1

class AdbBlocksReader:
    def __init__(self, stream: AdbStream):
        self.stream = stream

    def maybe_read_block(self) -> Optional[AdbBlock]:
        type_size_bytes = self.stream.read_exact_or_none(4, "block type/size")
        if type_size_bytes is None:
            return None
        type_size = _uint_from(type_size_bytes)
        type_block_raw = type_size >> 30
        size_raw = type_size & 0x3fffffff
        if type_block_raw == AdbBlockType.EXT:
            type_block = AdbBlockType(size_raw)
            _ = self.stream.skip(4, "ext block header reserved field (u32)")
            size_raw = _uint_from(self.stream.read_exact(8, "AdbBlock.x_size"))
            size_header = 16
        else:
            type_block = AdbBlockType(type_block_raw)
            size_header = 4
        if size_raw < size_header:
            panic(f"Invalid block raw size {size_raw} < {size_header}")
        return AdbBlock(type_block, size_raw, size_raw - size_header)

    def read_block(self) -> AdbBlock:
        block = self.maybe_read_block()
        if block is None:
            panic("Failed to read an ADB block")
        return block

    def pad(self, size_raw: int):
        remainder = size_raw & 7
        if remainder:
            self.stream.skip(8 - remainder, "ADB block padding")

    def parse_package(self, path_json: Optional[Path], path_tar: Optional[Path], checksum_tar: bool):
        logger.debug("Parsing package")

        block = self.read_block()
        logger.debug(block)
        apk_metainfo = AdbBlockAdbReader(self.stream.read_exact(block.size_payload, "ADB_BLOCK_ADB")).parse_apk()
        if path_json:
            with path_json.open("w") as f:
                json.dump(apk_metainfo.as_json_dict(), f)

        self.pad(block.size_raw)
        block = self.maybe_read_block()

        while block is not None and block.type_block == AdbBlockType.SIG:
            logger.debug(block)
            buffer = self.stream.read_exact(block.size_payload, "buffer for sig")
            hash_type = ApkHashType(buffer[1])
            match hash_type:
                case ApkHashType.SHA1 | ApkHashType.SHA256_160:
                    size_hash = 20
                case ApkHashType.SHA256:
                    size_hash = 32
                case ApkHashType.SHA512:
                    size_hash = 64
                case _:
                    self.pad(block.size_raw)
                    block = self.maybe_read_block()
                    continue
            logger.info(f"Hash {hash_type}, {size_hash} bytes, ID {buffer[2:18].hex()}: {_str_b64_from_bytes(buffer[18:])}")
            del buffer
            self.pad(block.size_raw)
            block = self.maybe_read_block()

        with ExitStack() as stack:
            if path_tar:
                tar_handler = stack.enter_context(ApkRootTarWriter(path_tar, apk_metainfo.paths, self.stream, checksum_tar))
            else:
                tar_handler = None
            while block is not None and block.type_block == AdbBlockType.DATA:
                logger.debug(block)
                id_dir = _uint_from(self.stream.read_exact(4, "path_idx"))
                id_file = _uint_from(self.stream.read_exact(4, "file_idx"))
                size_data = block.size_payload - 8
                logger.debug(f"Data for dir {id_dir} fie {id_file}, size {size_data}")
                if tar_handler is None:
                    self.stream.skip(size_data, "ADB_BLOCK_DATA")
                else:
                    tar_handler.add(id_dir, id_file, size_data)
                self.pad(block.size_raw)
                block = self.maybe_read_block()

        if block is not None:
            panic(f"Trailing ADB_BLOCK {block.type_block} at the end of ADB blocks", AdbFormatError)

    def parse_index(self, path_json: Optional[Path]):
        block = self.read_block()
        logger.debug(block)
        index = AdbBlockAdbReader(self.stream.read_exact(block.size_payload, "ADB_BLOCK_ADB")).parse_index()
        if path_json:
            with path_json.open("w") as f:
                json.dump(index.as_json_dict(), f)

def dump(path_adb: Path, path_json: Optional[Path], path_tar: Optional[Path], checksum_tar: bool):
    with path_adb.open("rb") as f:
        header = f.read(4)
        if len(header) < 4:
            panic("File too small, meanless to dump")
        if header[0:3] != b"ADB":
            panic(f"File header (first 3 bytes) is not b'ADB' (BE 0x616462), but BE 0x{header[0]:x}{header[1]:x}{header[2]:x}", AdbFormatError)
        match header[3]:
            case AdbCompressionWay.NONE:
                stream = RawAdbStream(f)
            case AdbCompressionWay.DEFLATE:
                stream = DeflateAdbStream(f)
                stream.lossy_assert_raw()
            case AdbCompressionWay.CUSTOM:
                alg = f.read(1)[0]
                _ = f.read(1)[0]
                match alg:
                    case AdbCompressionAlg.NONE:
                        stream = RawAdbStream(f)
                    case AdbCompressionAlg.DEFLATE:
                        stream = DeflateAdbStream(f)
                        stream.lossy_assert_raw()
                    case AdbCompressionAlg.ZSTD:
                        if zstd is None:
                            panic("Zstd compression not supported on current Python installation")
                        stream = ZstandardAdbStream(f)
                        stream.lossy_assert_raw()
                    case _:
                        panic(f"Invalid compression alg ID {alg} ", AdbFormatError)
            case _:
                panic(f"Invalid compression magic {header[3]:x}", AdbFormatError)
        del header
        schema = _uint_from(stream.read_exact(4, "schema"))
        match schema:
            case AdbSchema.PACKAGE:
                logger.info(f"Dumping APK {path_adb}; json: {path_json}; tar: {path_tar} (checksum: {checksum_tar})")
                AdbBlocksReader(stream).parse_package(path_json, path_tar, checksum_tar)
            case AdbSchema.INDEX:
                logger.info(f"Dumping Index {path_adb}; json: {path_json}")
                AdbBlocksReader(stream).parse_index(path_json)
            case _:
                panic(f"Unknown schema {schema:#x}", AdbFormatError)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("adb", type=Path, help="Either .apk or index .adb")
    parser.add_argument("--log", metavar="level", choices=("DEBUG", "INFO", "WARNING", "ERROR", "FATAL", "CRITICAL"), type=str.upper, default="INFO")
    parser.add_argument("--json", type=Path, help="Dump the info JSON into said file")
    parser.add_argument("--tar", type=Path, help="Convert the apk into a tar")
    parser.add_argument("--tarsum", action="store_true", help="When using --tar, add APK-TOOLS.checksum.* PAX headers")
    args = parser.parse_args()

    logging._levelToName = {
        logging.DEBUG:      '\33[37mDEBUG...\33[0m',
        logging.INFO:       '\33[36mINFO....\33[0m',
        logging.WARNING:    '\33[33mWARNING!\33[0m',
        logging.ERROR:      '\33[35mERROR!!!\33[0m',
        logging.FATAL:      '\33[31mFATAL!!!\33[0m',
        logging.NOTSET:            '........',
    }
    logging.basicConfig(stream=sys.stdout, format="%(levelname)s %(message)s", level=args.log)

    dump(args.adb, args.json, args.tar, args.tarsum)
