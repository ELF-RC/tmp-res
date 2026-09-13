"""EXT4 image extraction — 统一模块。

内部按职责分为两个模块：
  §1  EXT4 底层     — 文件系统结构体、Volume/Inode/BlockReader（原 ext4.py）
  §2  Image 提取    — sparse/EXT4 镜像提取与转换（原 extract_img.py）

外部接口保持不变：
  from scripts.ext4_handler import ULTRAMAN
  from scripts.ext4_handler import ext4  （兼容引用）
"""

from __future__ import annotations

import codecs
import ctypes
import io
import json
import mmap
import os
import queue
import re
import struct
from functools import cmp_to_key
from math import log as log_math
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════
#  §1  EXT4 底层 — 结构体、Volume、Inode、BlockReader
# ═══════════════════════════════════════════════════════════════════════════


def _wcs_cmp(str_a, str_b):
    for a, b in zip(str_a, str_b):
        tmp = ord(a) - ord(b)
        if tmp != 0:
            return -1 if tmp < 0 else 1
    tmp = len(str_a) - len(str_b)
    return -1 if tmp < 0 else 1 if tmp > 0 else 0


class Ext4Error(Exception):
    ...


class EndOfStreamError(Ext4Error):
    ...


class MagicError(Ext4Error):
    ...


# ── LOW LEVEL STRUCTS ─────────────────────────────────────────────────

class ext4_struct(ctypes.LittleEndianStructure):
    def __getattr__(self, name):
        try:
            lo_field = ctypes.LittleEndianStructure.__getattribute__(type(self), name + "_lo")
            size = lo_field.size
            lo = lo_field.__get__(self)
            hi = ctypes.LittleEndianStructure.__getattribute__(self, name + "_hi")
            return (hi << (8 * size)) | lo
        except AttributeError:
            return ctypes.LittleEndianStructure.__getattribute__(self, name)

    def __setattr__(self, name, value):
        try:
            lo_field = ctypes.LittleEndianStructure.__getattribute__(type(self), name + "_lo")
            size = lo_field.size
            lo_field.__set__(self, value & ((1 << (8 * size)) - 1))
            ctypes.LittleEndianStructure.__setattr__(self, name + "_hi", value >> (8 * size))
        except AttributeError:
            ctypes.LittleEndianStructure.__setattr__(self, name, value)


class ext4_dir_entry_2(ext4_struct):
    _fields_ = [
        ("inode", ctypes.c_uint),
        ("rec_len", ctypes.c_ushort),
        ("name_len", ctypes.c_ubyte),
        ("file_type", ctypes.c_ubyte),
    ]

    @staticmethod
    def _from_buffer_copy(raw, offset=0, platform64=True):
        s = ext4_dir_entry_2.from_buffer_copy(raw, offset)
        s.name = raw[offset + 0x8: offset + 0x8 + s.name_len]
        return s


class ext4_extent(ext4_struct):
    _fields_ = [
        ("ee_block", ctypes.c_uint),
        ("ee_len", ctypes.c_ushort),
        ("ee_start_hi", ctypes.c_ushort),
        ("ee_start_lo", ctypes.c_uint),
    ]


class ext4_extent_header(ext4_struct):
    _fields_ = [
        ("eh_magic", ctypes.c_ushort),
        ("eh_entries", ctypes.c_ushort),
        ("eh_max", ctypes.c_ushort),
        ("eh_depth", ctypes.c_ushort),
        ("eh_generation", ctypes.c_uint),
    ]


class ext4_extent_idx(ext4_struct):
    _fields_ = [
        ("ei_block", ctypes.c_uint),
        ("ei_leaf_lo", ctypes.c_uint),
        ("ei_leaf_hi", ctypes.c_ushort),
        ("ei_unused", ctypes.c_ushort),
    ]


class ext4_group_descriptor(ext4_struct):
    _fields_ = [
        ("bg_block_bitmap_lo", ctypes.c_uint),
        ("bg_inode_bitmap_lo", ctypes.c_uint),
        ("bg_inode_table_lo", ctypes.c_uint),
        ("bg_free_blocks_count_lo", ctypes.c_ushort),
        ("bg_free_inodes_count_lo", ctypes.c_ushort),
        ("bg_used_dirs_count_lo", ctypes.c_ushort),
        ("bg_flags", ctypes.c_ushort),
        ("bg_exclude_bitmap_lo", ctypes.c_uint),
        ("bg_block_bitmap_csum_lo", ctypes.c_ushort),
        ("bg_inode_bitmap_csum_lo", ctypes.c_ushort),
        ("bg_itable_unused_lo", ctypes.c_ushort),
        ("bg_checksum", ctypes.c_ushort),
        ("bg_block_bitmap_hi", ctypes.c_uint),
        ("bg_inode_bitmap_hi", ctypes.c_uint),
        ("bg_inode_table_hi", ctypes.c_uint),
        ("bg_free_blocks_count_hi", ctypes.c_ushort),
        ("bg_free_inodes_count_hi", ctypes.c_ushort),
        ("bg_used_dirs_count_hi", ctypes.c_ushort),
        ("bg_itable_unused_hi", ctypes.c_ushort),
        ("bg_exclude_bitmap_hi", ctypes.c_uint),
        ("bg_block_bitmap_csum_hi", ctypes.c_ushort),
        ("bg_inode_bitmap_csum_hi", ctypes.c_ushort),
        ("bg_reserved", ctypes.c_uint),
    ]

    @staticmethod
    def _from_buffer_copy(raw, platform64=True):
        s = ext4_group_descriptor.from_buffer_copy(raw)
        if not platform64:
            for attr in ('bg_block_bitmap_hi', 'bg_inode_bitmap_hi', 'bg_inode_table_hi',
                         'bg_free_blocks_count_hi', 'bg_free_inodes_count_hi', 'bg_used_dirs_count_hi',
                         'bg_itable_unused_hi', 'bg_exclude_bitmap_hi', 'bg_block_bitmap_csum_hi',
                         'bg_inode_bitmap_csum_hi', 'bg_reserved'):
                setattr(s, attr, 0)
        return s


class ext4_inode(ext4_struct):
    EXT2_GOOD_OLD_INODE_SIZE = 128

    S_IXOTH = 0x1
    S_IWOTH = 0x2
    S_IROTH = 0x4
    S_IXGRP = 0x8
    S_IWGRP = 0x10
    S_IRGRP = 0x20
    S_IXUSR = 0x40
    S_IWUSR = 0x80
    S_IRUSR = 0x100
    S_ISVTX = 0x200
    S_ISGID = 0x400
    S_ISUID = 0x800
    S_IFIFO = 0x1000
    S_IFCHR = 0x2000
    S_IFDIR = 0x4000
    S_IFBLK = 0x6000
    S_IFREG = 0x8000
    S_IFLNK = 0xA000
    S_IFSOCK = 0xC000

    EXT4_INDEX_FL = 0x1000
    EXT4_EXTENTS_FL = 0x80000
    EXT4_EA_INODE_FL = 0x200000
    EXT4_INLINE_DATA_FL = 0x10000000

    _fields_ = [
        ("i_mode", ctypes.c_ushort),
        ("i_uid_lo", ctypes.c_ushort),
        ("i_size_lo", ctypes.c_uint),
        ("i_atime", ctypes.c_uint),
        ("i_ctime", ctypes.c_uint),
        ("i_mtime", ctypes.c_uint),
        ("i_dtime", ctypes.c_uint),
        ("i_gid_lo", ctypes.c_ushort),
        ("i_links_count", ctypes.c_ushort),
        ("i_blocks_lo", ctypes.c_uint),
        ("i_flags", ctypes.c_uint),
        ("osd1", ctypes.c_uint),
        ("i_block", ctypes.c_uint * 15),
        ("i_generation", ctypes.c_uint),
        ("i_file_acl_lo", ctypes.c_uint),
        ("i_size_hi", ctypes.c_uint),
        ("i_obso_faddr", ctypes.c_uint),
        ("i_osd2_blocks_high", ctypes.c_ushort),
        ("i_file_acl_hi", ctypes.c_ushort),
        ("i_uid_hi", ctypes.c_ushort),
        ("i_gid_hi", ctypes.c_ushort),
        ("i_osd2_checksum_lo", ctypes.c_ushort),
        ("i_osd2_reserved", ctypes.c_ushort),
        ("i_extra_isize", ctypes.c_ushort),
        ("i_checksum_hi", ctypes.c_ushort),
        ("i_ctime_extra", ctypes.c_uint),
        ("i_mtime_extra", ctypes.c_uint),
        ("i_atime_extra", ctypes.c_uint),
        ("i_crtime", ctypes.c_uint),
        ("i_crtime_extra", ctypes.c_uint),
        ("i_version_hi", ctypes.c_uint),
        ("i_projid", ctypes.c_uint),
    ]


class ext4_superblock(ext4_struct):
    EXT2_DESC_SIZE = 0x20
    EXT2_MIN_DESC_SIZE = 0x20
    EXT2_MIN_DESC_SIZE_64BIT = 0x40
    INCOMPAT_64BIT = 0x80
    INCOMPAT_32BIT = 0x66
    INCOMPAT_FILETYPE = 0x2

    _fields_ = [
        ("s_inodes_count", ctypes.c_uint),
        ("s_blocks_count_lo", ctypes.c_uint),
        ("s_r_blocks_count_lo", ctypes.c_uint),
        ("s_free_blocks_count_lo", ctypes.c_uint),
        ("s_free_inodes_count", ctypes.c_uint),
        ("s_first_data_block", ctypes.c_uint),
        ("s_log_block_size", ctypes.c_uint),
        ("s_log_cluster_size", ctypes.c_uint),
        ("s_blocks_per_group", ctypes.c_uint),
        ("s_clusters_per_group", ctypes.c_uint),
        ("s_inodes_per_group", ctypes.c_uint),
        ("s_mtime", ctypes.c_uint),
        ("s_wtime", ctypes.c_uint),
        ("s_mnt_count", ctypes.c_ushort),
        ("s_max_mnt_count", ctypes.c_ushort),
        ("s_magic", ctypes.c_ushort),
        ("s_state", ctypes.c_ushort),
        ("s_errors", ctypes.c_ushort),
        ("s_minor_rev_level", ctypes.c_ushort),
        ("s_lastcheck", ctypes.c_uint),
        ("s_checkinterval", ctypes.c_uint),
        ("s_creator_os", ctypes.c_uint),
        ("s_rev_level", ctypes.c_uint),
        ("s_def_resuid", ctypes.c_ushort),
        ("s_def_resgid", ctypes.c_ushort),
        ("s_first_ino", ctypes.c_uint),
        ("s_inode_size", ctypes.c_ushort),
        ("s_block_group_nr", ctypes.c_ushort),
        ("s_feature_compat", ctypes.c_uint),
        ("s_feature_incompat", ctypes.c_uint),
        ("s_feature_ro_compat", ctypes.c_uint),
        ("s_uuid", ctypes.c_ubyte * 16),
        ("s_volume_name", ctypes.c_char * 16),
        ("s_last_mounted", ctypes.c_char * 64),
        ("s_algorithm_usage_bitmap", ctypes.c_uint),
        ("s_prealloc_blocks", ctypes.c_ubyte),
        ("s_prealloc_dir_blocks", ctypes.c_ubyte),
        ("s_reserved_gdt_blocks", ctypes.c_ushort),
        ("s_journal_uuid", ctypes.c_ubyte * 16),
        ("s_journal_inum", ctypes.c_uint),
        ("s_journal_dev", ctypes.c_uint),
        ("s_last_orphan", ctypes.c_uint),
        ("s_hash_seed", ctypes.c_uint * 4),
        ("s_def_hash_version", ctypes.c_ubyte),
        ("s_jnl_backup_type", ctypes.c_ubyte),
        ("s_desc_size", ctypes.c_ushort),
        ("s_default_mount_opts", ctypes.c_uint),
        ("s_first_meta_bg", ctypes.c_uint),
        ("s_mkfs_time", ctypes.c_uint),
        ("s_jnl_blocks", ctypes.c_uint * 17),
        ("s_blocks_count_hi", ctypes.c_uint),
        ("s_r_blocks_count_hi", ctypes.c_uint),
        ("s_free_blocks_count_hi", ctypes.c_uint),
        ("s_min_extra_isize", ctypes.c_ushort),
        ("s_want_extra_isize", ctypes.c_ushort),
        ("s_flags", ctypes.c_uint),
        ("s_raid_stride", ctypes.c_ushort),
        ("s_mmp_interval", ctypes.c_ushort),
        ("s_mmp_block", ctypes.c_ulonglong),
        ("s_raid_stripe_width", ctypes.c_uint),
        ("s_log_groups_per_flex", ctypes.c_ubyte),
        ("s_checksum_type", ctypes.c_ubyte),
        ("s_reserved_pad", ctypes.c_ushort),
        ("s_kbytes_written", ctypes.c_ulonglong),
        ("s_snapshot_inum", ctypes.c_uint),
        ("s_snapshot_id", ctypes.c_uint),
        ("s_snapshot_r_blocks_count", ctypes.c_ulonglong),
        ("s_snapshot_list", ctypes.c_uint),
        ("s_error_count", ctypes.c_uint),
        ("s_first_error_time", ctypes.c_uint),
        ("s_first_error_ino", ctypes.c_uint),
        ("s_first_error_block", ctypes.c_ulonglong),
        ("s_first_error_func", ctypes.c_ubyte * 32),
        ("s_first_error_line", ctypes.c_uint),
        ("s_last_error_time", ctypes.c_uint),
        ("s_last_error_ino", ctypes.c_uint),
        ("s_last_error_line", ctypes.c_uint),
        ("s_last_error_block", ctypes.c_ulonglong),
        ("s_last_error_func", ctypes.c_ubyte * 32),
        ("s_mount_opts", ctypes.c_ubyte * 64),
        ("s_usr_quota_inum", ctypes.c_uint),
        ("s_grp_quota_inum", ctypes.c_uint),
        ("s_overhead_blocks", ctypes.c_uint),
        ("s_backup_bgs", ctypes.c_uint * 2),
        ("s_encrypt_algos", ctypes.c_ubyte * 4),
        ("s_encrypt_pw_salt", ctypes.c_ubyte * 16),
        ("s_lpf_ino", ctypes.c_uint),
        ("s_prj_quota_inum", ctypes.c_uint),
        ("s_checksum_seed", ctypes.c_uint),
        ("s_reserved", ctypes.c_uint * 98),
        ("s_checksum", ctypes.c_uint),
    ]

    @staticmethod
    def _from_buffer_copy(raw, platform64=True):
        s = ext4_superblock.from_buffer_copy(raw)
        if not platform64:
            for attr in ('s_blocks_count_hi', 's_r_blocks_count_hi', 's_free_blocks_count_hi',
                         's_min_extra_isize', 's_want_extra_isize', 's_flags', 's_raid_stride',
                         's_mmp_interval', 's_mmp_block', 's_raid_stripe_width', 's_log_groups_per_flex',
                         's_checksum_type', 's_reserved_pad', 's_kbytes_written', 's_snapshot_inum',
                         's_snapshot_id', 's_snapshot_r_blocks_count', 's_snapshot_list', 's_error_count',
                         's_first_error_time', 's_first_error_ino', 's_first_error_block', 's_first_error_func',
                         's_first_error_line', 's_last_error_time', 's_last_error_ino', 's_last_error_line',
                         's_last_error_block', 's_last_error_func', 's_mount_opts', 's_usr_quota_inum',
                         's_grp_quota_inum', 's_overhead_blocks', 's_backup_bgs', 's_encrypt_algos',
                         's_encrypt_pw_salt', 's_lpf_ino', 's_prj_quota_inum', 's_checksum_seed',
                         's_reserved', 's_checksum'):
                setattr(s, attr, 0)
        if s.s_desc_size == 0:
            if (s.s_feature_incompat & ext4_superblock.INCOMPAT_64BIT) == 0:
                s.s_desc_size = ext4_superblock.EXT2_MIN_DESC_SIZE
            else:
                s.s_desc_size = ext4_superblock.EXT2_MIN_DESC_SIZE_64BIT
        return s


class ext4_xattr_entry(ext4_struct):
    _fields_ = [
        ("e_name_len", ctypes.c_ubyte),
        ("e_name_index", ctypes.c_ubyte),
        ("e_value_offs", ctypes.c_ushort),
        ("e_value_inum", ctypes.c_uint),
        ("e_value_size", ctypes.c_uint),
        ("e_hash", ctypes.c_uint),
    ]

    @staticmethod
    def _from_buffer_copy(raw, offset=0, platform64=True):
        s = ext4_xattr_entry.from_buffer_copy(raw, offset)
        s.e_name = raw[offset + 0x10: offset + 0x10 + s.e_name_len]
        return s

    @property
    def _size(self):
        return 4 * ((ctypes.sizeof(type(self)) + self.e_name_len + 3) // 4)


class ext4_xattr_header(ext4_struct):
    _fields_ = [
        ("h_magic", ctypes.c_uint),
        ("h_refcount", ctypes.c_uint),
        ("h_blocks", ctypes.c_uint),
        ("h_hash", ctypes.c_uint),
        ("h_checksum", ctypes.c_uint),
        ("h_reserved", ctypes.c_uint * 3),
    ]


class ext4_xattr_ibody_header(ext4_struct):
    _fields_ = [
        ("h_magic", ctypes.c_uint),
    ]


class InodeType:
    UNKNOWN = 0x0
    FILE = 0x1
    DIRECTORY = 0x2
    CHARACTER_DEVICE = 0x3
    BLOCK_DEVICE = 0x4
    FIFO = 0x5
    SOCKET = 0x6
    SYMBOLIC_LINK = 0x7
    CHECKSUM = 0xDE


# ── HIGH LEVEL ────────────────────────────────────────────────────────

class MappingEntry:
    def __init__(self, file_block_idx, disk_block_idx, block_count=1):
        self.file_block_idx = file_block_idx
        self.disk_block_idx = disk_block_idx
        self.block_count = block_count

    def __iter__(self):
        yield self.file_block_idx
        yield self.disk_block_idx
        yield self.block_count

    def __repr__(self):
        return f"{type(self).__name__:s}({self.file_block_idx!r:s}, {self.disk_block_idx!r:s}, {self.block_count!r:s})"

    def copy(self):
        return MappingEntry(self.file_block_idx, self.disk_block_idx, self.block_count)

    def create_mapping(*entries):
        file_block_idx = 0
        result = [None] * len(entries)
        for i, entry in enumerate(entries):
            disk_block_idx, block_count = entry
            result[i] = MappingEntry(file_block_idx, disk_block_idx, block_count)
            file_block_idx += block_count
        return result

    @staticmethod
    def optimize(entries):
        entries.sort(key=lambda entry: entry.file_block_idx)
        idx = 0
        while idx < len(entries):
            while (idx + 1 < len(entries)
                   and entries[idx].file_block_idx + entries[idx].block_count == entries[idx + 1].file_block_idx
                   and entries[idx].disk_block_idx + entries[idx].block_count == entries[idx + 1].disk_block_idx):
                tmp = entries.pop(idx + 1)
                entries[idx].block_count += tmp.block_count
            idx += 1


class Volume:
    ROOT_INODE = 2

    def __init__(self, stream, offset=0, ignore_flags=False, ignore_magic=False):
        self.ignore_flags = ignore_flags
        self.ignore_magic = ignore_magic
        self.offset = offset
        self.platform64 = True
        self.stream = stream
        self.superblock = self.read_struct(ext4_superblock, 0x400)
        self.platform64 = (self.superblock.s_feature_incompat & ext4_superblock.INCOMPAT_64BIT) != 0
        if not ignore_magic and self.superblock.s_magic != 0xEF53:
            raise MagicError(f"Invalid magic value in superblock: 0x{self.superblock.s_magic:04X} (expected 0xEF53)")
        self.group_descriptors = [None] * (self.superblock.s_inodes_count // self.superblock.s_inodes_per_group)
        group_desc_table_offset = (0x400 // self.block_size + 1) * self.block_size
        for group_desc_idx in range(len(self.group_descriptors)):
            group_desc_offset = group_desc_table_offset + group_desc_idx * self.superblock.s_desc_size
            self.group_descriptors[group_desc_idx] = self.read_struct(ext4_group_descriptor, group_desc_offset)

    def __repr__(self):
        return f"{type(self).__name__:s}(volume_name = {self.superblock.s_volume_name!r:s}, uuid = {self.uuid!r:s})"

    @property
    def block_size(self):
        return 1 << (10 + self.superblock.s_log_block_size)

    @property
    def get_block_count(self):
        return self.superblock.s_blocks_count

    @property
    def get_mount_point(self):
        return self.superblock.s_last_mounted.decode()

    @property
    def get_info_list(self):
        return [
            ['Filesystem magic number', hex(self.superblock.s_magic).upper()],
            ["Filesystem volume name", self.superblock.s_volume_name.decode()],
            ["Filesystem UUID", self.uuid],
            ['Last mounted on', self.superblock.s_last_mounted.decode()],
            ["Block size", f"{1 << (10 + self.superblock.s_log_block_size)}"],
            ["Block count", self.superblock.s_blocks_count],
            ["Free inodes", self.superblock.s_free_inodes_count],
            ["Free blocks", self.superblock.s_free_blocks_count],
            ["Inodes per group", self.superblock.s_inodes_per_group],
            ['Blocks per group', self.superblock.s_blocks_per_group],
            ['Inode count', self.superblock.s_inodes_count],
            ['Reserved GDT blocks', self.superblock.s_reserved_gdt_blocks],
            ["Inode size", self.superblock.s_inode_size],
            ['Filesystem created', self.superblock.s_mkfs_time],
            ["Currect Size", self.get_block_count * self.block_size],
        ]

    def get_inode(self, inode_idx, file_type=InodeType.UNKNOWN):
        group_idx, inode_table_entry_idx = self.get_inode_group(inode_idx)
        try:
            inode_table_offset = self.group_descriptors[group_idx].bg_inode_table * self.block_size
        except Exception:
            inode_table_offset = 99 * self.block_size
        inode_offset = inode_table_offset + inode_table_entry_idx * self.superblock.s_inode_size
        return Inode(self, inode_offset, inode_idx, file_type)

    def get_inode_group(self, inode_idx):
        group_idx = (inode_idx - 1) // self.superblock.s_inodes_per_group
        inode_table_entry_idx = (inode_idx - 1) % self.superblock.s_inodes_per_group
        return group_idx, inode_table_entry_idx

    def read(self, offset, byte_len):
        if self.offset + offset != self.stream.tell():
            self.stream.seek(self.offset + offset, io.SEEK_SET)
        return self.stream.read(byte_len)

    def read_struct(self, structure, offset, platform64=None):
        raw = self.read(offset, ctypes.sizeof(structure))
        if hasattr(structure, "_from_buffer_copy"):
            return structure._from_buffer_copy(raw, platform64=platform64 if platform64 else self.platform64)
        return structure.from_buffer_copy(raw)

    @property
    def root(self):
        return self.get_inode(Volume.ROOT_INODE, InodeType.DIRECTORY)

    @property
    def uuid(self):
        uuid = self.superblock.s_uuid
        uuid = [uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]]
        return "-".join("".join("{0:02X}".format(c) for c in part) for part in uuid)


class Inode:
    def __init__(self, volume, offset, inode_idx, file_type=InodeType.UNKNOWN):
        self.inode_idx = inode_idx
        self.offset = offset
        self.volume = volume
        self.file_type = file_type
        self.inode = volume.read_struct(ext4_inode, offset)

    def __len__(self):
        return self.inode.i_size

    def __repr__(self):
        if self.inode_idx is not None:
            return f"{type(self).__name__:s}(inode_idx = {self.inode_idx!r:s}, offset = 0x{self.offset:X})"
        return f"{type(self).__name__:s}(offset = 0x{self.offset:X})"

    def _parse_xattrs(self, raw_data, offset):
        prefixes = {
            0: "", 1: "user.", 2: "system.posix_acl_access", 3: "system.posix_acl_default",
            4: "trusted.", 6: "security.", 7: "system.", 8: "system.richacl",
        }
        i = 0
        while i < len(raw_data):
            xattr_entry = ext4_xattr_entry._from_buffer_copy(raw_data, i, platform64=self.volume.platform64)
            if not (xattr_entry.e_name_len | xattr_entry.e_name_index | xattr_entry.e_value_offs | xattr_entry.e_value_inum):
                break
            if xattr_entry.e_name_index not in prefixes:
                raise Ext4Error(f"Unknown attribute prefix {xattr_entry.e_name_index:d} in inode {self.inode_idx:d}")
            xattr_name = prefixes[xattr_entry.e_name_index] + xattr_entry.e_name.decode("iso-8859-2")
            if xattr_entry.e_value_inum != 0:
                xattr_inode = self.volume.get_inode(xattr_entry.e_value_inum, InodeType.FILE)
                if not self.volume.ignore_flags and (xattr_inode.inode.i_flags & ext4_inode.EXT4_EA_INODE_FL) != 0:
                    raise Ext4Error(f"Inode {xattr_inode.inode_idx:d} not marked as large xattr value.")
                xattr_value = xattr_inode.open_read().read()
            else:
                xattr_value = raw_data[xattr_entry.e_value_offs + offset: xattr_entry.e_value_offs + offset + xattr_entry.e_value_size]
            yield xattr_name, xattr_value
            i += xattr_entry._size

    @staticmethod
    def directory_entry_comparator(dir_a, dir_b):
        file_name_a, _, file_type_a = dir_a
        file_name_b, _, file_type_b = dir_b
        if file_type_a == InodeType.DIRECTORY == file_type_b or file_type_a != InodeType.DIRECTORY != file_type_b:
            tmp = _wcs_cmp(file_name_a.lower(), file_name_b.lower())
            return tmp if tmp != 0 else _wcs_cmp(file_name_a, file_name_b)
        return -1 if file_type_a == InodeType.DIRECTORY else 1

    directory_entry_key = cmp_to_key(directory_entry_comparator)

    def get_inode(self, *relative_path, decode_name=None):
        if not self.is_dir:
            raise Ext4Error(f"Inode {self.inode_idx:d} is not a directory.")
        current_inode = self
        for i, part in enumerate(relative_path):
            if not self.volume.ignore_flags and not current_inode.is_dir:
                raise Ext4Error(f"{'/'.join(relative_path[:i])!r} is not a directory.")
            file_name, inode_idx, file_type = next(
                filter(lambda entry: entry[0] == part, current_inode.open_dir(decode_name)), (None, None, None))
            if inode_idx is None:
                raise FileNotFoundError(f"{part!r} not found in {'/'.join(relative_path[:i])!r}")
            current_inode = current_inode.volume.get_inode(inode_idx, file_type)
        return current_inode

    @property
    def is_dir(self):
        if (self.volume.superblock.s_feature_incompat & ext4_superblock.INCOMPAT_FILETYPE) == 0:
            return (self.inode.i_mode & ext4_inode.S_IFDIR) != 0
        return self.file_type == InodeType.DIRECTORY

    @property
    def is_file(self):
        if (self.volume.superblock.s_feature_incompat & ext4_superblock.INCOMPAT_FILETYPE) == 0:
            return (self.inode.i_mode & ext4_inode.S_IFREG) != 0
        return self.file_type == InodeType.FILE

    @property
    def is_symlink(self):
        if (self.volume.superblock.s_feature_incompat & ext4_superblock.INCOMPAT_FILETYPE) == 0:
            return (self.inode.i_mode & ext4_inode.S_IFLNK) != 0
        return self.file_type == InodeType.SYMBOLIC_LINK

    @property
    def is_in_use(self):
        group_idx, bitmap_bit = self.volume.get_inode_group(self.inode_idx)
        inode_usage_bitmap_offset = self.volume.group_descriptors[group_idx].bg_inode_bitmap * self.volume.block_size
        inode_usage_byte = self.volume.read(inode_usage_bitmap_offset + bitmap_bit // 8, 1)[0]
        return ((inode_usage_byte >> (7 - bitmap_bit % 8)) & 1) != 0

    @property
    def mode_str(self):
        def special_flag(letter, execute, special):
            return {(False, False): "-", (False, True): letter.upper(), (True, False): "x", (True, True): letter.lower()}[(execute, special)]
        try:
            if (self.volume.superblock.s_feature_incompat & ext4_superblock.INCOMPAT_FILETYPE) == 0:
                device_type = {
                    ext4_inode.S_IFIFO: "p", ext4_inode.S_IFCHR: "c", ext4_inode.S_IFDIR: "d",
                    ext4_inode.S_IFBLK: "b", ext4_inode.S_IFREG: "-", ext4_inode.S_IFLNK: "l",
                    ext4_inode.S_IFSOCK: "s",
                }[self.inode.i_mode & 0xF000]
            else:
                device_type = {
                    InodeType.FILE: "-", InodeType.DIRECTORY: "d", InodeType.CHARACTER_DEVICE: "c",
                    InodeType.BLOCK_DEVICE: "b", InodeType.FIFO: "p", InodeType.SOCKET: "s",
                    InodeType.SYMBOLIC_LINK: "l",
                }[self.file_type]
        except KeyError:
            device_type = "?"
        return "".join([
            device_type,
            "r" if (self.inode.i_mode & ext4_inode.S_IRUSR) != 0 else "-",
            "w" if (self.inode.i_mode & ext4_inode.S_IWUSR) != 0 else "-",
            special_flag("s", (self.inode.i_mode & ext4_inode.S_IXUSR) != 0, (self.inode.i_mode & ext4_inode.S_ISUID) != 0),
            "r" if (self.inode.i_mode & ext4_inode.S_IRGRP) != 0 else "-",
            "w" if (self.inode.i_mode & ext4_inode.S_IWGRP) != 0 else "-",
            special_flag("s", (self.inode.i_mode & ext4_inode.S_IXGRP) != 0, (self.inode.i_mode & ext4_inode.S_ISGID) != 0),
            "r" if (self.inode.i_mode & ext4_inode.S_IROTH) != 0 else "-",
            "w" if (self.inode.i_mode & ext4_inode.S_IWOTH) != 0 else "-",
            special_flag("t", (self.inode.i_mode & ext4_inode.S_IXOTH) != 0, (self.inode.i_mode & ext4_inode.S_ISVTX) != 0),
        ])

    def open_dir(self, decode_name=None):
        if decode_name is None:
            decode_name = lambda raw: raw.decode("utf8")
        if not self.volume.ignore_flags and not self.is_dir:
            raise Ext4Error(f"Inode ({self.inode_idx:d}) is not a directory.")
        if (self.inode.i_flags & ext4_inode.EXT4_INDEX_FL) != 0:
            ...
        raw_data = self.open_read().read()
        offset = 0
        while offset < len(raw_data):
            dirent = ext4_dir_entry_2._from_buffer_copy(raw_data, offset, platform64=self.volume.platform64)
            if dirent.file_type != InodeType.CHECKSUM:
                yield decode_name(dirent.name), dirent.inode, dirent.file_type
            offset += dirent.rec_len

    def open_read(self):
        if (self.inode.i_flags & ext4_inode.EXT4_EXTENTS_FL) != 0:
            mapping = []
            nodes = queue.Queue()
            nodes.put_nowait(self.offset + ext4_inode.i_block.offset)
            while nodes.qsize() != 0:
                header_offset = nodes.get_nowait()
                header = self.volume.read_struct(ext4_extent_header, header_offset)
                if not self.volume.ignore_magic and header.eh_magic != 0xF30A:
                    raise MagicError(f"Invalid extent header magic: 0x{header.eh_magic:04X}")
                if header.eh_depth != 0:
                    indices = self.volume.read_struct(ext4_extent_idx * header.eh_entries,
                                                      header_offset + ctypes.sizeof(ext4_extent_header))
                    for idx in indices:
                        nodes.put_nowait(idx.ei_leaf * self.volume.block_size)
                else:
                    extents = self.volume.read_struct(ext4_extent * header.eh_entries,
                                                      header_offset + ctypes.sizeof(ext4_extent_header))
                    for extent in extents:
                        mapping.append(MappingEntry(extent.ee_block, extent.ee_start, extent.ee_len))
            MappingEntry.optimize(mapping)
            return BlockReader(self.volume, len(self), mapping)
        else:
            i_block = self.volume.read(self.offset + ext4_inode.i_block.offset, ext4_inode.i_block.size)
            return io.BytesIO(i_block[:self.inode.i_size])

    @property
    def size_readable(self):
        if self.inode.i_size < 1024:
            return "{0:d} bytes".format(self.inode.i_size) if self.inode.i_size != 1 else "1 byte"
        units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
        unit_idx = min(int(log_math(self.inode.i_size, 1024)), len(units))
        return f"{self.inode.i_size / (1024 ** unit_idx):.2f} {units[unit_idx - 1]:s}"

    def xattrs(self, check_inline=True, check_block=True, force_inline=False):
        inline_data_offset = self.offset + ext4_inode.EXT2_GOOD_OLD_INODE_SIZE + self.inode.i_extra_isize
        inline_data_length = self.offset + self.volume.superblock.s_inode_size - inline_data_offset
        if check_inline and inline_data_length > ctypes.sizeof(ext4_xattr_ibody_header):
            inline_data = self.volume.read(inline_data_offset, inline_data_length)
            xattrs_header = ext4_xattr_ibody_header.from_buffer_copy(inline_data)
            if force_inline or xattrs_header.h_magic == 0xEA020000:
                offset = 4 * ((ctypes.sizeof(ext4_xattr_ibody_header) + 3) // 4)
            try:
                for xattr_name, xattr_value in self._parse_xattrs(inline_data[offset:], 0):
                    yield xattr_name, xattr_value
            except Exception:
                ...
        if check_block and self.inode.i_file_acl != 0:
            xattrs_block_start = self.inode.i_file_acl * self.volume.block_size
            xattrs_block = self.volume.read(xattrs_block_start, self.volume.block_size)
            if xattrs_block:
                xattrs_header = ext4_xattr_header.from_buffer_copy(xattrs_block)
                if not self.volume.ignore_magic and xattrs_header.h_magic != 0xEA020000:
                    print(f"Invalid xattrs block header magic: 0x{xattrs_header.h_magic}")
                    return '', ''
                if xattrs_header.h_blocks != 1:
                    print(f"Invalid xattr blocks count: {xattrs_header.h_blocks:d}")
                    return '', ''
            offset = 4 * ((ctypes.sizeof(ext4_xattr_header) + 3) // 4)
            for xattr_name, xattr_value in self._parse_xattrs(xattrs_block[offset:], -offset):
                yield xattr_name, xattr_value


class BlockReader:
    EINVAL = 22

    def __init__(self, volume, byte_size, block_map):
        self.byte_size = byte_size
        self.volume = volume
        self.cursor = 0
        block_map = list(map(MappingEntry.copy, block_map))
        MappingEntry.optimize(block_map)
        self.block_map = block_map

    def __repr__(self):
        return f"{type(self).__name__:s}(byte_size = {self.byte_size!r:s}, block_map = {self.block_map!r:s})"

    def get_block_mapping(self, file_block_idx):
        disk_block_idx = None
        for entry in self.block_map:
            if entry.file_block_idx <= file_block_idx < entry.file_block_idx + entry.block_count:
                block_diff = file_block_idx - entry.file_block_idx
                disk_block_idx = entry.disk_block_idx + block_diff
                break
        return disk_block_idx

    def read(self, byte_len=-1):
        if byte_len < -1:
            raise ValueError("byte_len must be non-negative or -1")
        bytes_remaining = self.byte_size - self.cursor
        byte_len = bytes_remaining if byte_len == -1 else max(0, min(byte_len, bytes_remaining))
        if byte_len == 0:
            return b""
        start_block_idx = self.cursor // self.volume.block_size
        end_block_idx = (self.cursor + byte_len - 1) // self.volume.block_size
        end_of_stream_check = byte_len
        blocks = [self.read_block(i) for i in range(start_block_idx, end_block_idx + 1)]
        start_offset = self.cursor % self.volume.block_size
        if start_offset != 0:
            blocks[0] = blocks[0][start_offset:]
        byte_len = (byte_len + start_offset - self.volume.block_size - 1) % self.volume.block_size + 1
        blocks[-1] = blocks[-1][:byte_len]
        result = b"".join(blocks)
        if len(result) != end_of_stream_check:
            raise EndOfStreamError("The volume's underlying stream ended {0:d} bytes before EOF.".format(byte_len - len(result)))
        self.cursor += len(result)
        return result

    def read_block(self, file_block_idx):
        disk_block_idx = self.get_block_mapping(file_block_idx)
        if disk_block_idx is not None:
            return self.volume.read(disk_block_idx * self.volume.block_size, self.volume.block_size)
        return bytes([0] * self.volume.block_size)

    def seek(self, seek, seek_mode=io.SEEK_SET):
        if seek_mode == io.SEEK_CUR:
            seek += self.cursor
        elif seek_mode == io.SEEK_END:
            seek += self.byte_size
        if seek < 0:
            raise OSError(BlockReader.EINVAL, "Invalid argument")
        self.cursor = seek
        return seek

    def tell(self):
        return self.cursor


# 便捷引用：让外部代码可以 `from scripts.extract_img import ext4` 然后用 ext4.Volume
import types as _types
ext4 = _types.ModuleType(__name__ + '.ext4')
for _name in ('Ext4Error', 'EndOfStreamError', 'MagicError', 'ext4_struct',
              'ext4_dir_entry_2', 'ext4_extent', 'ext4_extent_header', 'ext4_extent_idx',
              'ext4_group_descriptor', 'ext4_inode', 'ext4_superblock',
              'ext4_xattr_entry', 'ext4_xattr_header', 'ext4_xattr_ibody_header',
              'InodeType', 'MappingEntry', 'Volume', 'Inode', 'BlockReader'):
    setattr(ext4, _name, locals()[_name])


# ═══════════════════════════════════════════════════════════════════════════
#  §2  Image 提取 — sparse/EXT4 镜像提取与转换
# ═══════════════════════════════════════════════════════════════════════════

SPARSE_HEADER_MAGIC = 0xED26FF3A
EXT4_RAW_HEADER_MAGIC = 0xED26FF3A
EXT4_SPARSE_HEADER_LEN = 28
EXT4_CHUNK_HEADER_SIZE = 12
LP_METADATA_HEADER_MAGIC = 1095520304
EROFS_HEADER_MAGIC = 0xE0F5E1E2


class ImageExtractionError(RuntimeError):
    """Raised when an image cannot be extracted without data loss."""


class EXT4_IMAGE_HEADER(object):
    def __init__(self, buf):
        (self.magic, self.major, self.minor, self.file_header_size, self.chunk_header_size, self.block_size,
         self.total_blocks, self.total_chunks, self.crc32) = struct.unpack('<I4H4I', buf)


class EXT4_CHUNK_HEADER(object):
    def __init__(self, buf):
        (self.type, self.reserved, self.chunk_size, self.total_size) = struct.unpack('<2H2I', buf)


def is_valid_ext4_directory_entry(entry_name, entry_inode_idx):
    """Return whether an EXT4 directory entry points to a real filesystem node."""
    return (
        entry_inode_idx != 0
        and isinstance(entry_name, str)
        and entry_name not in {'', '.', '..'}
    )


class ULTRAMAN(object):

    def __init__(self):
        self.FileName = ''
        self.BASE_DIR = ''
        self.OUTPUT_IMAGE_FILE = ''
        self.EXTRACT_DIR = ''
        self.contexts = []
        self.fsconfig = []
        self.space = []

    def __file_name(self, file_path):
        name = os.path.basename(file_path).split('.img')[0]
        name = name.split('.unsparse')[0]
        name = name.replace('/', '\\')
        return name

    @staticmethod
    def __appendf(msg, log):
        Path(log).parent.mkdir(parents=True, exist_ok=True)
        with open(log, 'w', encoding='utf-8', newline='\n') as file:
            print(msg, file=file)

    def __getperm(self, arg):
        if len(arg) < 9 or len(arg) > 10:
            return
        if len(arg) > 8:
            arg = arg[1:]
        oor, ow, ox, gr, gw, gx, wr, ww, wx = list(arg)
        o, g, w, s = 0, 0, 0, 0
        if oor == 'r': o += 4
        if ow == 'w': o += 2
        if ox == 'x': o += 1
        if ox == 'S': s += 4
        if ox == 's': s += 4; o += 1
        if gr == 'r': g += 4
        if gw == 'w': g += 2
        if gx == 'x': g += 1
        if gx == 'S': s += 2
        if gx == 's': s += 2; g += 1
        if wr == 'r': w += 4
        if ww == 'w': w += 2
        if wx == 'x': w += 1
        if wx == 'T': s += 1
        if wx == 't': s += 1; w += 1
        return str(s) + str(o) + str(g) + str(w)

    def checkSignOffset(self, file):
        size = os.stat(file.name).st_size
        length = 0 if size <= 52428800 else 52428800
        with mmap.mmap(file.fileno(), length, access=mmap.ACCESS_READ) as mm:
            return mm.find(struct.pack('<L', EXT4_RAW_HEADER_MAGIC))

    def __ImgSizeFromSparseFile(self, target):
        img_file = open(target, 'rb')
        if self.sign_offset > 0:
            img_file.seek(self.sign_offset, 0)
        header = EXT4_IMAGE_HEADER(img_file.read(28))
        imgsize = header.block_size * header.total_blocks
        img_file.close()
        return imgsize

    @staticmethod
    def __ImgSizeFromRawFile(target):
        with open(target, 'rb') as img_file:
            m = ''
            see = 1028
            for i in reversed(range(4)):
                img_file.seek(see + i)
                m += img_file.read(1).hex()
            imgsize = int('0x' + m, 16) * 4096
        return imgsize

    def GetImageType(self, target):
        filename, file_extension = os.path.splitext(target)
        if file_extension == '.img':
            with open(target, "rb") as img_file:
                setattr(self, 'sign_offset', self.checkSignOffset(img_file))
                if self.sign_offset > 0:
                    img_file.seek(self.sign_offset, 0)
                header = EXT4_IMAGE_HEADER(img_file.read(28))
                if header.magic != EXT4_RAW_HEADER_MAGIC:
                    return 'img'
                else:
                    return 'simg'

    def FIX_MOTO(self, input_file):
        if not os.path.exists(input_file):
            return
        output_file = input_file + "_"
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except Exception:
                pass
        with open(input_file, 'rb') as f:
            data = f.read(500000)
        moto = re.search(b'\x4d\x4f\x54\x4f', data)
        if not moto:
            return
        result = []
        for i in re.finditer(b'\x53\xEF', data):
            result.append(i.start() - 1080)
        offset = 0
        for i in result:
            if data[i] == 0:
                offset = i
                break
        if offset > 0:
            with open(output_file, 'wb') as o, open(input_file, 'rb') as f:
                data = f.seek(offset)
                data = f.read(15360)
                if data:
                    devnull = o.write(data)
        try:
            os.remove(input_file)
            os.rename(output_file, input_file)
        except Exception:
            pass

    def __fix_size(self):
        """Expand a truncated EXT4 image to the size recorded in its superblock."""
        orig_size = os.path.getsize(self.OUTPUT_IMAGE_FILE)
        with open(self.OUTPUT_IMAGE_FILE, 'rb+') as file:
            vol = Volume(file)
            real_size = vol.get_block_count * vol.block_size
            if orig_size < real_size:
                print(f'> EXT4 镜像被截断，扩展: {orig_size} -> {real_size}')
                file.truncate(real_size)

    def MONSTER(self, target, output_dir):
        output_dir = Path(output_dir)
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise ImageExtractionError(f'提取目录无效: {output_dir}')
        self.BASE_DIR = os.path.realpath(os.path.dirname(target)) + os.sep
        self.EXTRACT_DIR = str(output_dir.resolve()) + os.sep
        self.OUTPUT_IMAGE_FILE = self.BASE_DIR + os.path.basename(target)
        self.FileName = self.__file_name(os.path.basename(target))
        image_type = self.GetImageType(target)
        if image_type == 'simg':
            self.OUTPUT_IMAGE_FILE = self.Simg2Rimg(target)
        elif image_type != 'img':
            raise ImageExtractionError(f'无法识别 EXT4 镜像: {target}')
        with open(os.path.abspath(self.OUTPUT_IMAGE_FILE), 'rb') as stream:
            moto = re.search(b'MOTO', stream.read(500000))
        if moto:
            self.FIX_MOTO(os.path.abspath(self.OUTPUT_IMAGE_FILE))
        self.__fix_size()
        self.EXT4_EXTRACTOR()
        return True

    def LEMON(self, target):
        from scripts.utils import gettype, findfile
        if not os.path.exists(target):
            return 0
        target_type = gettype(target)
        if target_type == 'sparse':
            return self.__ImgSizeFromSparseFile(target)
        return os.path.getsize(target)

    def APPLE(self, target):
        target_type = self.GetImageType(target)
        if target_type == 'simg':
            return self.Simg2Rimg(target)

    def Simg2Rimg(self, target):
        """Convert Android sparse data while preserving RAW/FILL/DONT_CARE chunks."""
        def read_exact(stream, size, description):
            data = stream.read(size)
            if len(data) != size:
                raise ValueError(f'稀疏镜像{description}被截断')
            return data

        with open(target, 'rb') as img_file:
            if self.sign_offset > 0:
                img_file.seek(self.sign_offset, 0)
            header = EXT4_IMAGE_HEADER(read_exact(img_file, EXT4_SPARSE_HEADER_LEN, '文件头'))
            if header.magic != SPARSE_HEADER_MAGIC:
                raise ValueError(f'不是有效的稀疏镜像: {target}')
            if header.chunk_header_size < EXT4_CHUNK_HEADER_SIZE:
                raise ValueError(f'稀疏镜像 chunk header 无效: {target}')
            if header.file_header_size > EXT4_SPARSE_HEADER_LEN:
                read_exact(img_file, header.file_header_size - EXT4_SPARSE_HEADER_LEN, '扩展文件头')

            unsparse_file = target.replace('.img', '.unsparse.img')
            with open(unsparse_file, 'wb') as raw_img_file:
                for _ in range(header.total_chunks):
                    chunk_header = EXT4_CHUNK_HEADER(
                        read_exact(img_file, EXT4_CHUNK_HEADER_SIZE, 'chunk header')
                    )
                    if header.chunk_header_size > EXT4_CHUNK_HEADER_SIZE:
                        read_exact(img_file, header.chunk_header_size - EXT4_CHUNK_HEADER_SIZE, '扩展 chunk header')
                    chunk_data_size = chunk_header.total_size - header.chunk_header_size
                    output_size = chunk_header.chunk_size * header.block_size
                    if chunk_data_size < 0:
                        raise ValueError(f'稀疏镜像 chunk 大小无效: {target}')

                    if chunk_header.type == 0xCAC1:  # RAW
                        if chunk_data_size != output_size:
                            raise ValueError(f'稀疏镜像 RAW chunk 大小无效: {target}')
                        remaining = output_size
                        while remaining:
                            data = read_exact(img_file, min(1024 * 1024, remaining), 'RAW 数据')
                            raw_img_file.write(data)
                            remaining -= len(data)
                    elif chunk_header.type == 0xCAC2:  # FILL
                        if chunk_data_size != 4:
                            raise ValueError(f'稀疏镜像 FILL chunk 大小无效: {target}')
                        fill = read_exact(img_file, 4, 'FILL 数据')
                        if output_size % len(fill):
                            raise ValueError(f'稀疏镜像 FILL 输出大小无效: {target}')
                        pattern = fill * (min(1024 * 1024, output_size) // len(fill))
                        remaining = output_size
                        while remaining:
                            data = pattern[:min(len(pattern), remaining)]
                            raw_img_file.write(data)
                            remaining -= len(data)
                    elif chunk_header.type == 0xCAC3:  # DONT_CARE
                        if chunk_data_size:
                            read_exact(img_file, chunk_data_size, 'DONT_CARE 数据')
                        raw_img_file.seek(output_size, 1)
                    elif chunk_header.type == 0xCAC4:  # CRC32
                        if output_size:
                            raise ValueError(f'稀疏镜像 CRC chunk 输出大小无效: {target}')
                        read_exact(img_file, chunk_data_size, 'CRC 数据')
                    else:
                        raise ValueError(f'不支持的稀疏镜像 chunk 类型: {chunk_header.type:#x}')
                raw_img_file.truncate(raw_img_file.tell())
            return unsparse_file

    def EXT4_EXTRACTOR(self):
        output_root = Path(self.EXTRACT_DIR).resolve()
        config_dir = output_root.parent / 'config'
        if output_root.is_symlink() or not output_root.is_dir():
            raise ImageExtractionError(f'EXT4 输出目录无效: {output_root}')
        if config_dir.is_symlink():
            raise ImageExtractionError(f'EXT4 metadata 目录无效: {config_dir}')
        config_dir.mkdir(parents=True, exist_ok=True)

        contexts_path = config_dir / f'{self.FileName}_contexts.txt'
        fsconfig_path = config_dir / f'{self.FileName}_fsconfig.txt'
        info_path = config_dir / f'{self.FileName}_info.txt'
        space_path = config_dir / f'{self.FileName}_space.txt'
        partition_size = os.path.getsize(self.OUTPUT_IMAGE_FILE)
        with open(self.OUTPUT_IMAGE_FILE, 'rb') as filesystem:
            filesystem.seek(1024)
            superblock = filesystem.read(1024)
        if len(superblock) != 1024:
            raise ImageExtractionError(f'EXT4 superblock 被截断: {self.OUTPUT_IMAGE_FILE}')
        inode_count = struct.unpack_from('<L', superblock, 0)[0]
        block_size = 1024 << struct.unpack_from('<L', superblock, 24)[0]
        per_group = struct.unpack_from('<L', superblock, 32)[0]
        label = bytes(superblock[120:136]).rstrip(b'\x00').decode('utf-8', 'replace')
        manifest = {
            'a': inode_count, 'b': block_size, 'c': per_group,
            'd': label, 'e': 'ext4', 's': partition_size,
        }

        seen_targets = set()

        def output_path(components):
            if not components or any(
                not component or component in {'.', '..'} or '/' in component or '\\' in component
                or any(character.isspace() for character in component) or '"' in component
                for component in components
            ):
                raise ImageExtractionError(f'EXT4 包含无法安全表示的路径: {components!r}')
            target = output_root.joinpath(*components)
            try:
                target.relative_to(output_root)
            except ValueError as error:
                raise ImageExtractionError(f'EXT4 路径越界: {components!r}') from error
            if target in seen_targets:
                raise ImageExtractionError(f'EXT4 路径冲突: {target}')
            if target.parent.is_symlink() or not target.parent.is_dir():
                raise ImageExtractionError(f'EXT4 父目录无效: {target.parent}')
            seen_targets.add(target)
            return target

        def read_link(inode, vol):
            reader = inode.open_read()
            try:
                data = reader.read(65536)
                if reader.read(1):
                    raise ImageExtractionError('EXT4 符号链接目标过长')
            finally:
                close_reader = getattr(reader, 'close', None)
                if close_reader:
                    close_reader()
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                if len(data) > 8:
                    raise ImageExtractionError('EXT4 符号链接目标无法解码')
                block = int.from_bytes(data, 'little')
                return vol.read(block * vol.block_size, inode.inode.i_size).decode('utf-8')

        def write_file(inode, target):
            reader = inode.open_read()
            try:
                with open(target, 'xb') as out:
                    while True:
                        chunk = reader.read(1024 * 1024)
                        if not chunk:
                            break
                        if out.write(chunk) != len(chunk):
                            raise ImageExtractionError(f'EXT4 文件写入不完整: {target}')
            except OSError as error:
                raise ImageExtractionError(f'EXT4 文件写入失败: {target}: {error}') from error
            finally:
                close_reader = getattr(reader, 'close', None)
                if close_reader:
                    close_reader()

        def scan_dir(root_inode, components=()):
            for entry_name, entry_inode_idx, entry_type in root_inode.open_dir():
                if not is_valid_ext4_directory_entry(entry_name, entry_inode_idx):
                    continue
                entry_inode = root_inode.volume.get_inode(entry_inode_idx, entry_type)
                entry_components = (*components, entry_name)
                target = output_path(entry_components)
                mode = self.__getperm(entry_inode.mode_str)
                if mode is None:
                    raise ImageExtractionError(f'EXT4 文件权限无效: {entry_name!r}')
                uid = entry_inode.inode.i_uid
                gid = entry_inode.inode.i_gid
                relative_path = '/'.join(entry_components)
                fs_path = f'{self.FileName}/{relative_path}'
                cap = ''
                link_target = ''
                for attribute, value in entry_inode.xattrs():
                    if attribute == 'security.selinux':
                        escaped = fs_path
                        for character in '\\^$.|?*+(){}[]':
                            escaped = escaped.replace(character, '\\' + character)
                        self.contexts.append(f'/{escaped} {value.decode("utf-8").rstrip(chr(0))}')
                    elif attribute == 'security.capability':
                        values = struct.unpack('<5I', value)
                        if values[1] > 65535:
                            capability = hex(int(f'{values[3]:04x}{values[1]:04x}', 16))
                        else:
                            capability = hex(int(f'{values[3]:04x}{values[2]:04x}{values[1]:04x}', 16))
                        cap = f' capabilities={capability}'

                if entry_inode.is_dir:
                    try:
                        target.mkdir()
                    except OSError as error:
                        raise ImageExtractionError(f'EXT4 目录创建失败: {target}: {error}') from error
                    if os.geteuid() == 0:
                        os.chmod(target, int(mode, 8))
                        os.chown(target, uid, gid)
                    self.fsconfig.append(f'{fs_path} {uid} {gid} {mode}{cap}')
                    scan_dir(entry_inode, entry_components)
                elif entry_inode.is_file:
                    write_file(entry_inode, target)
                    if os.geteuid() == 0:
                        os.chmod(target, int(mode, 8))
                        os.chown(target, uid, gid)
                    self.fsconfig.append(f'{fs_path} {uid} {gid} {mode}{cap}')
                elif entry_inode.is_symlink:
                    link_target = read_link(entry_inode, root_inode.volume)
                    try:
                        os.symlink(link_target, target)
                    except OSError as error:
                        raise ImageExtractionError(f'EXT4 符号链接创建失败: {target}: {error}') from error
                    self.fsconfig.append(f'{fs_path} {uid} {gid} {mode}{cap} {link_target}')
                else:
                    raise ImageExtractionError(f'EXT4 包含不支持的文件类型: {entry_name!r}')

        with open(self.OUTPUT_IMAGE_FILE, 'rb') as image_file:
            scan_dir(Volume(image_file).root)

        partition_name = self.FileName
        self.fsconfig.insert(0, '/ 0 2000 0755' if partition_name == 'vendor' else '/ 0 0 0755')
        self.fsconfig.insert(1, f'{partition_name} 0 2000 0755' if partition_name == 'vendor' else '/lost+found 0 0 0700')
        self.fsconfig.insert(2 if partition_name == 'system' else 1, f'{partition_name} 0 0 0755')
        self.__appendf('\n'.join(self.fsconfig), fsconfig_path)
        self.__appendf('\n'.join(self.space), space_path)
        with codecs.open(info_path, 'w', 'utf-8') as stream:
            json.dump(manifest, stream, indent=4)
        if self.contexts:
            self.contexts.sort()
            root_context = None
            for context in self.contexts:
                fields = context.split(maxsplit=1)
                if len(fields) == 2 and re.search(r'lost.{2}found', context):
                    root_context = fields[1]
                    break
            if not root_context:
                root_context = 'u:object_r:rootfs:s0'
            if root_context:
                self.contexts.insert(0, f'/ {root_context}')
                self.contexts.insert(1, f'/{partition_name}(/.*)? {root_context}')
                self.contexts.insert(2, f'/{partition_name} {root_context}')
                self.contexts.insert(3, f'/{partition_name}/lost+\\found {root_context}')
        self.__appendf('\n'.join(self.contexts), contexts_path)
        return True
