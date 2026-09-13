# pylint: disable=line-too-long
"""Super image — 统一模块。

内部按职责分为三个模块：
  §1  LP Metadata   — 底层 LP 元数据结构体与解析（原 extract_super.py）
  §2  SparseImage   — Android sparse image 读取与 unsparse
  §3  LpUnpack      — super.img 解包核心类
  §4  Framework     — 工程目录集成 / A-B 槽位处理（原 extract_super_framework.py）
  §5  Selective     — 交互式选择性提取（原 extract_super_v2.py）

外部接口保持不变：
  from scripts.extract_super import unpack, get_parts          (§3)
  from scripts.extract_super import extract_super              (§4)
  from scripts.extract_super import main as selective_main     (§5)
"""

from __future__ import annotations

import argparse
import copy
import enum
import io
import json
import os
import re
import shutil
import struct
import sys
from dataclasses import dataclass, field
from string import Template
from timeit import default_timer as dti
from typing import IO, Dict, List, TypeVar, cast, BinaryIO, Tuple

# ═══════════════════════════════════════════════════════════════════════════
#  §1  LP Metadata — 底层结构体与常量
# ═══════════════════════════════════════════════════════════════════════════

SPARSE_HEADER_MAGIC = 0xED26FF3A
SPARSE_HEADER_SIZE = 28
SPARSE_CHUNK_HEADER_SIZE = 12

LP_PARTITION_RESERVED_BYTES = 4096
LP_METADATA_GEOMETRY_MAGIC = 0x616c4467
LP_METADATA_GEOMETRY_SIZE = 4096
LP_METADATA_HEADER_MAGIC = 0x414C5030
LP_SECTOR_SIZE = 512

LP_TARGET_TYPE_LINEAR = 0
LP_TARGET_TYPE_ZERO = 1

LP_PARTITION_ATTR_READONLY = (1 << 0)
LP_PARTITION_ATTR_SLOT_SUFFIXED = (1 << 1)
LP_PARTITION_ATTR_UPDATED = (1 << 2)
LP_PARTITION_ATTR_DISABLED = (1 << 3)

LP_BLOCK_DEVICE_SLOT_SUFFIXED = (1 << 0)
LP_GROUP_SLOT_SUFFIXED = (1 << 0)

PLAIN_TEXT_TEMPLATE = """Slot 0:
Metadata version: $metadata_version
Metadata size: $metadata_size bytes
Metadata max size: $metadata_max_size bytes
Metadata slot count: $metadata_slot_count
Header flags: $header_flags
Partition table:
------------------------
$partitions
------------------------
Super partition layout:
------------------------
$layouts
------------------------
Block device table:
------------------------
$blocks
------------------------
Group table:
------------------------
$groups
"""


def _build_attribute_string(attributes: int) -> str:
    if attributes & LP_PARTITION_ATTR_READONLY:
        return "readonly"
    elif attributes & LP_PARTITION_ATTR_SLOT_SUFFIXED:
        return "slot-suffixed"
    elif attributes & LP_PARTITION_ATTR_UPDATED:
        return "updated"
    elif attributes & LP_PARTITION_ATTR_DISABLED:
        return "disabled"
    return "none"


def _build_block_device_flag_string(flags: int) -> str:
    return "slot-suffixed" if (flags & LP_BLOCK_DEVICE_SLOT_SUFFIXED) else "none"


def _build_group_flag_string(flags: int) -> str:
    return "slot-suffixed" if (flags & LP_GROUP_SLOT_SUFFIXED) else "none"


class FormatType(enum.Enum):
    TEXT = "text"
    JSON = "json"


class EnumAction(argparse.Action):
    """Argparse action for handling Enums."""

    def __init__(self, **kwargs):
        enum_type = kwargs.pop("type", None)
        if enum_type is None:
            raise ValueError("Type must be assigned an Enum when using EnumAction")
        if not issubclass(enum_type, enum.Enum):
            raise TypeError("Type must be an Enum when using EnumAction")
        kwargs.setdefault("choices", tuple(e.value for e in enum_type))
        super().__init__(**kwargs)
        self._enum = enum_type

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, self._enum(values))


class ShowJsonInfo(json.JSONEncoder):
    def __init__(self, ignore_keys: List[str], **kwargs):
        super().__init__(**kwargs)
        self._ignore_keys = ignore_keys

    def _remove_ignore_keys(self, data: Dict):
        _data = copy.deepcopy(data)
        for field_key, v in data.items():
            if field_key in self._ignore_keys:
                _data.pop(field_key)
                continue
            if v == 0:
                _data.pop(field_key)
                continue
            if isinstance(v, int) and not isinstance(v, bool):
                _data.update({field_key: str(v)})
        return _data

    def encode(self, data: Dict) -> str:
        result = {
            "partitions": list(map(self._remove_ignore_keys, data["partition_table"])),
            "groups": list(map(self._remove_ignore_keys, data["group_table"])),
            "block_devices": list(map(self._remove_ignore_keys, data["block_devices"])),
        }
        return super().encode(result)


class SparseHeader:
    def __init__(self, buffer):
        fmt = '<I4H4I'
        (self.magic, self.major_version, self.minor_version, self.file_hdr_sz,
         self.chunk_hdr_sz, self.blk_sz, self.total_blks, self.total_chunks,
         self.image_checksum) = struct.unpack(fmt, buffer[0:struct.calcsize(fmt)])


class SparseChunkHeader:
    def __init__(self, buffer):
        fmt = '<2H2I'
        (self.chunk_type, self.reserved, self.chunk_sz,
         self.total_sz) = struct.unpack(fmt, buffer[0:struct.calcsize(fmt)])


class LpMetadataBase:
    _fmt = None

    @classmethod
    @property
    def size(cls) -> int:
        return struct.calcsize(cls._fmt)


class LpMetadataGeometry(LpMetadataBase):
    _fmt = '<2I32s3I'

    def __init__(self, buffer):
        (self.magic, self.struct_size, self.checksum,
         self.metadata_max_size, self.metadata_slot_count,
         self.logical_block_size) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])


class LpMetadataTableDescriptor(LpMetadataBase):
    _fmt = '<3I'

    def __init__(self, buffer):
        (self.offset, self.num_entries,
         self.entry_size) = struct.unpack(self._fmt, buffer[:struct.calcsize(self._fmt)])


class LpMetadataPartition(LpMetadataBase):
    _fmt = '<36s4I'

    def __init__(self, buffer):
        (self.name, self.attributes, self.first_extent_index,
         self.num_extents, self.group_index) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])
        self.name = self.name.decode("utf-8").strip('\x00')

    @property
    def filename(self) -> str:
        return f'{self.name}.img'


class LpMetadataExtent(LpMetadataBase):
    _fmt = '<QIQI'

    def __init__(self, buffer):
        (self.num_sectors, self.target_type, self.target_data,
         self.target_source) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])


class LpMetadataHeader(LpMetadataBase):
    _fmt = '<I2hI32sI32s'
    partitions: LpMetadataTableDescriptor = field(default=None)
    extents: LpMetadataTableDescriptor = field(default=None)
    groups: LpMetadataTableDescriptor = field(default=None)
    block_devices: LpMetadataTableDescriptor = field(default=None)

    def __init__(self, buffer):
        (self.magic, self.major_version, self.minor_version, self.header_size,
         self.header_checksum, self.tables_size,
         self.tables_checksum) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])
        self.flags = 0


class LpMetadataPartitionGroup(LpMetadataBase):
    _fmt = '<36sIQ'

    def __init__(self, buffer):
        (self.name, self.flags,
         self.maximum_size) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])
        self.name = self.name.decode("utf-8").strip('\x00')


class LpMetadataBlockDevice(LpMetadataBase):
    _fmt = '<Q2IQ36sI'

    def __init__(self, buffer):
        (self.first_logical_sector, self.alignment, self.alignment_offset,
         self.block_device_size, self.partition_name,
         self.flags) = struct.unpack(self._fmt, buffer[0:struct.calcsize(self._fmt)])
        self.partition_name = self.partition_name.decode("utf-8").strip('\x00')


@dataclass
class Metadata:
    header: LpMetadataHeader = field(default=None)
    geometry: LpMetadataGeometry = field(default=None)
    partitions: List[LpMetadataPartition] = field(default_factory=list)
    extents: List[LpMetadataExtent] = field(default_factory=list)
    groups: List[LpMetadataPartitionGroup] = field(default_factory=list)
    block_devices: List[LpMetadataBlockDevice] = field(default_factory=list)

    @property
    def info(self) -> Dict:
        return self._get_info()

    @property
    def metadata_region(self) -> int:
        if self.geometry is None:
            return 0
        return LP_PARTITION_RESERVED_BYTES + (
            LP_METADATA_GEOMETRY_SIZE + self.geometry.metadata_max_size * self.geometry.metadata_slot_count
        ) * 2

    def _get_extents_string(self, partition: LpMetadataPartition) -> List[str]:
        result = []
        first_sector = 0
        for extent_number in range(partition.num_extents):
            index = partition.first_extent_index + extent_number
            extent = self.extents[index]
            _base = f"{first_sector} .. {first_sector + extent.num_sectors - 1}"
            first_sector += extent.num_sectors
            if extent.target_type == LP_TARGET_TYPE_LINEAR:
                result.append(
                    f"{_base} linear {self.block_devices[extent.target_source].partition_name} {extent.target_data}"
                )
            elif extent.target_type == LP_TARGET_TYPE_ZERO:
                result.append(f"{_base} zero")
        return result

    def _get_partition_layout(self) -> List[str]:
        result = []
        for partition in self.partitions:
            for extent_number in range(partition.num_extents):
                index = partition.first_extent_index + extent_number
                extent = self.extents[index]
                block_device_name = ""
                if extent.target_type == LP_TARGET_TYPE_LINEAR:
                    block_device_name = self.block_devices[extent.target_source].partition_name
                result.append(
                    f"{block_device_name}: {extent.target_data} .. {extent.target_data + extent.num_sectors}: "
                    f"{partition.name} ({extent.num_sectors} sectors)"
                )
        return result

    def get_offsets(self, slot_number: int = 0) -> List[int]:
        base = LP_PARTITION_RESERVED_BYTES + (LP_METADATA_GEOMETRY_SIZE * 2)
        _tmp_offset = self.geometry.metadata_max_size * slot_number
        primary_offset = base + _tmp_offset
        backup_offset = base + self.geometry.metadata_max_size * self.geometry.metadata_slot_count + _tmp_offset
        return [primary_offset, backup_offset]

    def _get_info(self) -> Dict:
        result = {}
        try:
            result = {
                "metadata_version": f"{self.header.major_version}.{self.header.minor_version}",
                "metadata_size": self.header.header_size + self.header.tables_size,
                "metadata_max_size": self.geometry.metadata_max_size,
                "metadata_slot_count": self.geometry.metadata_slot_count,
                "header_flags": "none",
                "block_devices": [
                    {
                        "name": item.partition_name,
                        "first_sector": item.first_logical_sector,
                        "size": item.block_device_size,
                        "block_size": self.geometry.logical_block_size,
                        "flags": _build_block_device_flag_string(item.flags),
                        "alignment": item.alignment,
                        "alignment_offset": item.alignment_offset,
                    } for item in self.block_devices
                ],
                "group_table": [
                    {
                        "name": self.groups[index].name,
                        "maximum_size": self.groups[index].maximum_size,
                        "flags": _build_group_flag_string(self.groups[index].flags),
                    } for index in range(0, self.header.groups.num_entries)
                ],
                "partition_table": [
                    {
                        "name": item.name,
                        "group_name": self.groups[item.group_index].name,
                        "is_dynamic": True,
                        "size": self.extents[item.first_extent_index].num_sectors * LP_SECTOR_SIZE,
                        "attributes": _build_attribute_string(item.attributes),
                        "extents": self._get_extents_string(item),
                    } for item in self.partitions
                ],
                "partition_layout": self._get_partition_layout(),
            }
        except Exception:
            ...
        finally:
            return result

    @property
    def get_info2(self):
        parts = {}
        for item in self.partitions:
            parts[self.groups[item.group_index].name] = parts[self.groups[item.group_index].name] + item.name
        return parts

    def to_json(self) -> str:
        data = self._get_info()
        if not data:
            return ""
        return json.dumps(
            data, indent=1, cls=ShowJsonInfo,
            ignore_keys=[
                'metadata_version', 'metadata_size', 'metadata_max_size',
                'metadata_slot_count', 'header_flags', 'partition_layout',
                'attributes', 'extents', 'flags', 'first_sector',
            ],
        )

    def __str__(self):
        data = self._get_info()
        if not data:
            return ""
        template = Template(PLAIN_TEXT_TEMPLATE)
        layouts = "\n".join(data["partition_layout"])
        partitions = "------------------------\n".join(
            [
                "  Name: {}\n  Group: {}\n  Attributes: {}\n  Extents:\n    {}\n".format(
                    item["name"], item["group_name"], item["attributes"],
                    "\n".join(item["extents"]),
                ) for item in data["partition_table"]
            ]
        )[:-1]
        blocks = "\n".join(
            [
                f"  Partition name: {item['name']}\n  First sector: {item['first_sector']}\n  Size: {item['size']} bytes\n  Flags: {item['flags']}"
                for item in data["block_devices"]
            ]
        )
        groups = "------------------------\n".join(
            [
                f"  Name: {item['name']}\n  Maximum size: {item['maximum_size']} bytes\n  Flags: {item['flags']}\n"
                for item in data["group_table"]
            ]
        )[:-1]
        return template.substitute(
            partitions=partitions, layouts=layouts, blocks=blocks,
            groups=groups, **data,
        )


class LpUnpackError(Exception):
    """Raised on any error during LP unpacking."""

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


_SAFE_PARTITION_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')


def _validate_partition_name(name):
    if not isinstance(name, str) or not _SAFE_PARTITION_NAME.fullmatch(name):
        raise LpUnpackError(f'Invalid logical partition name: {name!r}')
    return name


@dataclass
class UnpackJob:
    name: str
    geometry: LpMetadataGeometry
    parts: List[Tuple[int, int]] = field(default_factory=list)
    total_size: int = field(default=0)


# ═══════════════════════════════════════════════════════════════════════════
#  §2  SparseImage — Android sparse image 读取与 unsparse
# ═══════════════════════════════════════════════════════════════════════════

class SparseImage:
    """Read Android sparse images without loading large chunks into memory."""

    _IO_CHUNK_SIZE = 1024 * 1024

    def __init__(self, fd):
        self._fd = fd
        self.header = None

    def _read_exact(self, size, description):
        data = self._fd.read(size)
        if len(data) != size:
            raise LpUnpackError(f'Sparse image {description} is truncated.')
        return data

    def check(self):
        self._fd.seek(0)
        header_data = self._fd.read(SPARSE_HEADER_SIZE)
        if len(header_data) < SPARSE_HEADER_SIZE:
            return False
        self.header = SparseHeader(header_data)
        return self.header.magic == SPARSE_HEADER_MAGIC

    def _skip_chunk_header_extension(self):
        extension_size = self.header.chunk_hdr_sz - SPARSE_CHUNK_HEADER_SIZE
        if extension_size < 0:
            raise LpUnpackError('Sparse image has an invalid chunk header size.')
        if extension_size:
            self._read_exact(extension_size, 'chunk header extension')

    def _consume(self, size, description):
        remaining = size
        while remaining:
            chunk = self._fd.read(min(remaining, self._IO_CHUNK_SIZE))
            if not chunk:
                raise LpUnpackError(f'Sparse image {description} is truncated.')
            remaining -= len(chunk)

    def _write_repeated(self, out, pattern, size):
        if not pattern:
            raise LpUnpackError('Sparse image fill pattern is empty.')
        block = (pattern * ((self._IO_CHUNK_SIZE + len(pattern) - 1) // len(pattern)))[:self._IO_CHUNK_SIZE]
        remaining = size
        while remaining:
            count = min(remaining, len(block))
            if out.write(block[:count]) != count:
                raise LpUnpackError('Failed to write unsparsed image.')
            remaining -= count

    def unsparse(self):
        if not self.header:
            self._fd.seek(0)
            self.header = SparseHeader(self._read_exact(SPARSE_HEADER_SIZE, 'header'))
        if self.header.magic != SPARSE_HEADER_MAGIC:
            raise LpUnpackError('Invalid sparse image magic.')
        if self.header.file_hdr_sz < SPARSE_HEADER_SIZE:
            raise LpUnpackError('Sparse image has an invalid file header size.')
        if self.header.chunk_hdr_sz < SPARSE_CHUNK_HEADER_SIZE:
            raise LpUnpackError('Sparse image has an invalid chunk header size.')
        if self.header.blk_sz <= 0:
            raise LpUnpackError('Sparse image has an invalid block size.')

        self._fd.seek(self.header.file_hdr_sz - SPARSE_HEADER_SIZE, 1)
        unsparse_file_dir = os.path.dirname(self._fd.name)
        unsparse_file = os.path.join(
            unsparse_file_dir,
            f"{os.path.splitext(os.path.basename(self._fd.name))[0]}.unsparse.img",
        )
        logical_size = 0
        with open(unsparse_file, 'wb') as out:
            for _ in range(self.header.total_chunks):
                chunk_header = SparseChunkHeader(
                    self._read_exact(SPARSE_CHUNK_HEADER_SIZE, 'chunk header')
                )
                self._skip_chunk_header_extension()
                output_size = chunk_header.chunk_sz * self.header.blk_sz
                chunk_data_size = chunk_header.total_sz - self.header.chunk_hdr_sz
                if chunk_data_size < 0:
                    raise LpUnpackError('Sparse image chunk size is invalid.')

                if chunk_header.chunk_type == 0xCAC1:  # RAW
                    if chunk_data_size != output_size:
                        raise LpUnpackError('Sparse RAW chunk size is invalid.')
                    remaining = output_size
                    while remaining:
                        size = min(self._IO_CHUNK_SIZE, remaining)
                        data = self._read_exact(size, 'RAW chunk')
                        if out.write(data) != size:
                            raise LpUnpackError('Failed to write unsparsed image.')
                        remaining -= size
                elif chunk_header.chunk_type == 0xCAC2:  # FILL
                    if chunk_data_size != 4:
                        raise LpUnpackError('Sparse FILL chunk size is invalid.')
                    fill = self._read_exact(4, 'FILL chunk')
                    self._write_repeated(out, fill, output_size)
                elif chunk_header.chunk_type == 0xCAC3:  # DONT_CARE
                    if chunk_data_size:
                        self._consume(chunk_data_size, 'DONT_CARE chunk')
                    out.seek(output_size, 1)
                elif chunk_header.chunk_type == 0xCAC4:  # CRC32
                    if output_size or chunk_data_size != 4:
                        raise LpUnpackError('Sparse CRC32 chunk size is invalid.')
                    self._read_exact(4, 'CRC32 chunk')
                else:
                    raise LpUnpackError(
                        f'Unsupported sparse chunk type: {chunk_header.chunk_type:#x}'
                    )
                logical_size += output_size

            expected_size = self.header.total_blks * self.header.blk_sz
            if logical_size != expected_size:
                raise LpUnpackError('Sparse image logical size does not match its header.')
            out.truncate(expected_size)
        return unsparse_file


# ═══════════════════════════════════════════════════════════════════════════
#  §3  LpUnpack — super.img 解包核心类
# ═══════════════════════════════════════════════════════════════════════════

T = TypeVar('T')


class LpUnpack:
    def __init__(self, **kwargs):
        self._partition_name = kwargs.get('NAME')
        self._show_info = kwargs.get('SHOW_INFO', True)
        self._show_info_format = kwargs.get('SHOW_INFO_FORMAT', FormatType.TEXT)
        self._config = kwargs.get('CONFIG', None)
        self._slot_num = None
        self._fd: BinaryIO = open(kwargs.get('SUPER_IMAGE'), 'rb')
        self._out_dir = kwargs.get('OUTPUT_DIR', None)

    def _check_out_dir_exists(self):
        if self._out_dir is None:
            return
        output_dir = os.path.abspath(self._out_dir)
        if os.path.islink(output_dir):
            raise LpUnpackError(f'Output directory cannot be a symbolic link: {output_dir}')
        if os.path.exists(output_dir) and not os.path.isdir(output_dir):
            raise LpUnpackError(f'Output path is not a directory: {output_dir}')
        os.makedirs(output_dir, exist_ok=True)
        self._out_dir = output_dir

    def _extract_partition(self, unpack_job: UnpackJob):
        self._check_out_dir_exists()
        name = _validate_partition_name(unpack_job.name)
        start = dti()
        print(f'Extracting partition [{name}]')
        output_dir = os.path.abspath(self._out_dir)
        out_file = os.path.abspath(os.path.join(output_dir, f'{name}.img'))
        if os.path.commonpath((output_dir, out_file)) != output_dir:
            raise LpUnpackError(f'Partition output escapes destination: {name!r}')
        if os.path.lexists(out_file) and os.path.islink(out_file):
            raise LpUnpackError(f'Partition output cannot be a symbolic link: {out_file}')
        with open(out_file, 'wb') as out:
            for part in unpack_job.parts:
                offset, size = part
                self._write_extent_to_file(out, offset, size, unpack_job.geometry.logical_block_size)
        print(f'Done:[{dti() - start}]')

    def _extract(self, partition, metadata):
        unpack_job = UnpackJob(name=partition.name, geometry=metadata.geometry)
        if partition.num_extents != 0:
            for extent_number in range(partition.num_extents):
                index = partition.first_extent_index + extent_number
                extent = metadata.extents[index]
                if extent.target_type != LP_TARGET_TYPE_LINEAR:
                    raise LpUnpackError(f'Unsupported target type in extent: {extent.target_type}')
                offset = extent.target_data * LP_SECTOR_SIZE
                size = extent.num_sectors * LP_SECTOR_SIZE
                unpack_job.parts.append((offset, size))
                unpack_job.total_size += size
        self._extract_partition(unpack_job)

    def _get_data(self, count: int, size: int, clazz: T) -> List[T]:
        result = []
        while count > 0:
            result.append(clazz(self._fd.read(size)))
            count -= 1
        return result

    def _read_metadata_header(self, metadata: Metadata):
        offsets = metadata.get_offsets()
        for index, offset in enumerate(offsets):
            self._fd.seek(offset, io.SEEK_SET)
            header = LpMetadataHeader(self._fd.read(80))
            header.partitions = LpMetadataTableDescriptor(self._fd.read(12))
            header.extents = LpMetadataTableDescriptor(self._fd.read(12))
            header.groups = LpMetadataTableDescriptor(self._fd.read(12))
            header.block_devices = LpMetadataTableDescriptor(self._fd.read(12))
            if header.magic != LP_METADATA_HEADER_MAGIC:
                check_index = index + 1
                if check_index > len(offsets):
                    raise LpUnpackError('Logical partition metadata has invalid magic value.')
                else:
                    print(f'Read Backup header by offset 0x{offsets[check_index]:x}')
                    continue
            metadata.header = header
            self._fd.seek(offset + header.header_size, io.SEEK_SET)

    def _read_metadata(self):
        self._fd.seek(LP_PARTITION_RESERVED_BYTES, io.SEEK_SET)
        metadata = Metadata(geometry=self._read_primary_geometry())
        if metadata.geometry.magic != LP_METADATA_GEOMETRY_MAGIC:
            raise LpUnpackError('Logical partition metadata has invalid geometry magic signature.')
        if metadata.geometry.metadata_slot_count == 0:
            raise LpUnpackError('Logical partition metadata has invalid slot count.')
        if metadata.geometry.metadata_max_size % LP_SECTOR_SIZE != 0:
            raise LpUnpackError('Metadata max size is not sector-aligned.')
        self._read_metadata_header(metadata)
        metadata.partitions = self._get_data(
            metadata.header.partitions.num_entries, metadata.header.partitions.entry_size, LpMetadataPartition)
        metadata.extents = self._get_data(
            metadata.header.extents.num_entries, metadata.header.extents.entry_size, LpMetadataExtent)
        metadata.groups = self._get_data(
            metadata.header.groups.num_entries, metadata.header.groups.entry_size, LpMetadataPartitionGroup)
        metadata.block_devices = self._get_data(
            metadata.header.block_devices.num_entries, metadata.header.block_devices.entry_size, LpMetadataBlockDevice)
        try:
            super_device: LpMetadataBlockDevice = cast(LpMetadataBlockDevice, iter(metadata.block_devices).__next__())
            if metadata.metadata_region > super_device.first_logical_sector * LP_SECTOR_SIZE:
                raise LpUnpackError('Logical partition metadata overlaps with logical partition contents.')
        except StopIteration:
            raise LpUnpackError('Metadata does not specify a super device.')
        return metadata

    def _read_primary_geometry(self) -> LpMetadataGeometry:
        geometry = LpMetadataGeometry(self._fd.read(LP_METADATA_GEOMETRY_SIZE))
        if geometry is not None:
            return geometry
        return LpMetadataGeometry(self._fd.read(LP_METADATA_GEOMETRY_SIZE))

    def _write_extent_to_file(self, fd: IO, offset: int, size: int, block_size: int):
        self._fd.seek(offset)
        remaining = size
        while remaining:
            block = self._fd.read(min(block_size, remaining))
            if not block:
                raise LpUnpackError('Super image ended before an extent was complete.')
            fd.write(block)
            remaining -= len(block)

    def _auto_unsparse(self):
        """检测 sparse 并自动转换，返回有效 fd 路径。"""
        if SparseImage(self._fd).check():
            print('Sparse image detected.')
            print('Process conversion to non sparse image...')
            unsparse_file = SparseImage(self._fd).unsparse()
            self._fd.close()
            self._fd = open(str(unsparse_file), 'rb')
            print('Result:[ok]')

    def get_info(self):
        try:
            self._auto_unsparse()
            self._fd.seek(0)
            metadata = self._read_metadata()
            filter_partition = [p.name for p in metadata.partitions]
            if not filter_partition:
                raise LpUnpackError(f'Could not find partition: {self._partition_name}')
            return filter_partition
        except LpUnpackError:
            raise
        finally:
            self._fd.close()

    def unpack(self):
        try:
            self._auto_unsparse()
            self._fd.seek(0)
            metadata = self._read_metadata()
            if self._partition_name:
                filter_partition = [p for p in metadata.partitions if p.name in self._partition_name]
                if not filter_partition:
                    raise LpUnpackError(f'Could not find partition: {self._partition_name}')
                metadata.partitions = filter_partition
            if self._slot_num:
                if self._slot_num > metadata.geometry.metadata_slot_count:
                    raise LpUnpackError(f'Invalid metadata slot number: {self._slot_num}')
            if self._show_info:
                if self._show_info_format == FormatType.TEXT:
                    print(metadata)
                elif self._show_info_format == FormatType.JSON:
                    print(f"{metadata.to_json()}\n")
            if not self._show_info and self._out_dir is None:
                raise LpUnpackError(message='Not specified directory for extraction')
            if self._out_dir:
                for partition in metadata.partitions:
                    self._extract(partition, metadata)
        except LpUnpackError:
            raise
        finally:
            self._fd.close()


def unpack(file: str, out: str, parts: list = None):
    """解包 super.img 到指定目录。"""
    namespace = argparse.Namespace(SUPER_IMAGE=file, OUTPUT_DIR=out, SHOW_INFO=False, NAME=parts)
    if not os.path.exists(namespace.SUPER_IMAGE):
        raise FileNotFoundError(f"{namespace.SUPER_IMAGE} Cannot Find")
    LpUnpack(**vars(namespace)).unpack()


def get_parts(file_: str):
    """获取 super.img 内所有分区名称列表。"""
    namespace = argparse.Namespace(SUPER_IMAGE=file_, SHOW_INFO=False)
    if not os.path.exists(namespace.SUPER_IMAGE):
        raise FileNotFoundError(f"{namespace.SUPER_IMAGE} Cannot Find")
    return LpUnpack(**vars(namespace)).get_info()


# ═══════════════════════════════════════════════════════════════════════════
#  §4  Framework — 工程目录集成 / A-B 槽位处理
# ═══════════════════════════════════════════════════════════════════════════

def _cleanup_super_ab(super_dir):
    """Clean up _a/_b suffixes in super_dir when user chooses not to continue extracting."""
    files = {Path(f).stem: Path(super_dir) / f for f in os.listdir(super_dir) if f.endswith('.img')}
    a_parts = {s[:-2]: p for s, p in files.items() if s.endswith('_a') and p.exists()}
    b_parts = {s[:-2]: p for s, p in files.items() if s.endswith('_b') and p.exists()}
    for part in sorted(set(a_parts) | set(b_parts)):
        pa = a_parts.get(part)
        pb = b_parts.get(part)
        size_a = pa.stat().st_size if pa and pa.exists() else 0
        size_b = pb.stat().st_size if pb and pb.exists() else 0
        if size_a == 0 and size_b == 0:
            for p in (pa, pb):
                if p and p.exists():
                    p.unlink()
        elif size_a > 0 and size_b > 0:
            pass
        elif size_a > 0:
            if pb and pb.exists():
                pb.unlink()
            dest = Path(super_dir) / f'{part}.img'
            if dest.exists():
                dest.unlink()
            pa.rename(dest)
        else:
            if pa and pa.exists():
                pa.unlink()
            dest = Path(super_dir) / f'{part}.img'
            if dest.exists():
                dest.unlink()
            pb.rename(dest)


def _move_super_images_to_out(super_dir):
    """Move remaining .img files from super_dir to OUT."""
    from scripts.utils import V as _V
    out_dir = _V.out
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    remaining = [f for f in os.listdir(super_dir) if f.endswith('.img')]
    if remaining:
        for name in sorted(remaining):
            src = Path(super_dir) / name
            dst = Path(out_dir) / name
            if dst.exists():
                dst.unlink()
            os.replace(str(src), str(dst))
            from scripts.utils import display
            display(f'已输出: {name} -> {out_dir}')


def extract_super(working_source, partition):
    """Extract a super.img into WORKSPACE.

    Returns True if handled (either extracted or moved to OUT), False on failure.
    """
    from scripts.utils import V as _V, display
    from scripts.workspace import workspace_partition, _super_images_to_process
    from scripts.extract_dispatch import decompress_img

    display(f'正在分解: {os.path.basename(working_source)} <super>', 3)
    super_dir = os.path.join(_V.workspace, 'super') + os.sep
    try:
        unpack(working_source, super_dir)
    except (Exception, SystemExit) as error:
        print(f'> super 分解失败: {error}')
        return False

    if input('> 是否继续分解img [0/1]: ') != '1':
        _cleanup_super_ab(super_dir)
        _move_super_images_to_out(super_dir)
        shutil.rmtree(super_dir, ignore_errors=True)
        return True

    for image, image_partition in _super_images_to_process(super_dir):
        decompress_img(image, workspace_partition(image_partition))
    shutil.rmtree(super_dir, ignore_errors=True)
    return True


# ═══════════════════════════════════════════════════════════════════════════
#  §5  Selective — 交互式选择性提取
# ═══════════════════════════════════════════════════════════════════════════

_SEL_YELLOW = '\x1b[1;33m'
_SEL_GREEN = '\x1b[1;32m'
_SEL_RED = '\x1b[91m'
_SEL_BOLD = '\x1b[1m'
_SEL_CLOSE = '\x1b[0m'


def _sel_get_input_dir():
    try:
        from scripts.utils import V as _V
        if _V and getattr(_V, 'input', None):
            return _V.input
    except Exception:
        pass
    for root in (os.getcwd(), os.path.dirname(os.getcwd())):
        for name in ("INPUT", "input"):
            p = os.path.join(root, name)
            if os.path.isdir(p):
                return p + os.sep
    return ""


def _sel_get_out_dir():
    try:
        from scripts.utils import V as _V
        if _V and getattr(_V, 'out', None):
            return _V.out
    except Exception:
        pass
    for root in (os.getcwd(), os.path.dirname(os.getcwd())):
        for name in ("OUT", "out"):
            p = os.path.join(root, name)
            if os.path.isdir(p):
                return p + os.sep
    return ""


def _human_size(b):
    """Convert bytes to human-readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.2f} GB"


def _list_partitions(super_img_path):
    """Parse super metadata and return (sorted_partition_info, effective_img_path)."""
    job = LpUnpack(SUPER_IMAGE=super_img_path, SHOW_INFO=False)
    effective_path = super_img_path
    if SparseImage(job._fd).check():
        print('Sparse image detected.')
        print('Process conversion to non sparse image...')
        unsparse_file = SparseImage(job._fd).unsparse()
        job._fd.close()
        effective_path = str(unsparse_file)
        job._fd = open(effective_path, 'rb')
        print('Result:[ok]')
    job._fd.seek(0)
    metadata = job._read_metadata()
    result = []
    for p in metadata.partitions:
        size = 0
        for ext_idx in range(p.num_extents):
            idx = p.first_extent_index + ext_idx
            if idx < len(metadata.extents):
                size += metadata.extents[idx].num_sectors * 512
        group = ""
        if 0 <= p.group_index < len(metadata.groups):
            group = metadata.groups[p.group_index].name
        result.append((p.name, group, size))
    job._fd.close()
    result.sort(key=lambda x: (-x[2], x[0]))
    return result, effective_path


def _show_partitions(partitions):
    """Print partition list, return indices of selected partitions."""
    if not partitions:
        print(f'{_SEL_RED}> 未发现任何分区{_SEL_CLOSE}')
        return []

    print(f'\n{_SEL_BOLD}发现 {len(partitions)} 个分区：{_SEL_CLOSE}\n')
    print(f'  {"序号":>4}  {"分区名":<20} {"组":<16} {"大小":>1}')
    print(f'  {"----":>6}  {"-" * 20} {"-" * 18} {"-" * 10}')
    for i, (name, group, size) in enumerate(partitions, 1):
        print(f'  {i:>4}    {name:<20} {group:<18} {_human_size(size):>9}')

    print(f'\n{_SEL_YELLOW}请输入要提取的分区序号（多个用逗号分隔，如 1,3,5）：{_SEL_CLOSE}')
    print(f'{_SEL_YELLOW}  输入 0 跳过（不提取任何分区）{_SEL_CLOSE}')
    print(f'{_SEL_YELLOW}  输入 all 全选{_SEL_CLOSE}')
    ans = input('> ').strip()
    if not ans or ans == '0':
        return []
    if ans.lower() == 'all':
        return list(range(len(partitions)))

    selected = []
    for token in ans.replace('，', ',').split(','):
        token = token.strip()
        if not token:
            continue
        try:
            idx = int(token)
            if 1 <= idx <= len(partitions):
                selected.append(idx - 1)
            else:
                print(f'  {_SEL_RED}无效序号: {idx}{_SEL_CLOSE}')
        except ValueError:
            print(f'  {_SEL_RED}无法解析: {token}{_SEL_CLOSE}')
    return selected


def _extract_selected(super_img_path, out_dir, partitions, selected_indices):
    """Extract selected partitions."""
    if not selected_indices:
        print(f'{_SEL_YELLOW}> 未选择任何分区，跳过提取{_SEL_CLOSE}')
        return
    names = [partitions[i][0] for i in selected_indices]
    print(f'\n{_SEL_BOLD}> 开始提取 {len(names)} 个分区：{", ".join(names)}{_SEL_CLOSE}')
    print(f'> 输出目录: {out_dir}\n')
    try:
        os.makedirs(out_dir, exist_ok=True)
        job = LpUnpack(
            SUPER_IMAGE=super_img_path,
            OUTPUT_DIR=out_dir,
            NAME=names,
            SHOW_INFO=False,
        )
        job.unpack()
        print(f'\n{_SEL_GREEN}> 提取完成！文件已输出到 {out_dir}{_SEL_CLOSE}\n')
    except Exception as e:
        print(f'{_SEL_RED}> 提取失败: {e}{_SEL_CLOSE}')


def main():
    """交互式选择性提取入口。"""
    os.system("clear")
    input_dir = _sel_get_input_dir()
    out_dir = _sel_get_out_dir()

    print('\n' * 8)
    print(f'{_SEL_YELLOW}          super 分区选择性提取{_SEL_CLOSE}\n')
    print(f'{_SEL_YELLOW}          请将 super.img 放入 INPUT 目录{_SEL_CLOSE}\n')
    input('          准备好后按回车继续...')

    if not input_dir:
        print(f'\n          {_SEL_RED}[!] 未找到 INPUT 目录，请确认运行位置正确{_SEL_CLOSE}')
        return

    super_path = os.path.join(input_dir, 'super.img')
    if not os.path.isfile(super_path):
        print(f'\n          {_SEL_RED}INPUT 目录下未发现 super.img ！{_SEL_CLOSE}\n')
        return

    if not out_dir:
        out_dir = input_dir.replace('INPUT', 'OUT') + os.sep

    os.system("clear")
    print(f'\n{_SEL_BOLD}> 正在读取 super 元数据...{_SEL_CLOSE}')
    partitions, effective_path = _list_partitions(super_path)

    if not partitions:
        print(f'{_SEL_RED}> super.img 内未发现分区或解析失败{_SEL_CLOSE}')
        input('> 任意键继续')
        return

    selected = _show_partitions(partitions)
    if selected:
        _extract_selected(effective_path, out_dir, partitions, selected)
