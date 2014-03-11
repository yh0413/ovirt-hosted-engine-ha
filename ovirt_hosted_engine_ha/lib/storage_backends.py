from collections import namedtuple
import os
import struct
import subprocess
import zlib
from ..env import constants
from . import util
import math
from cStringIO import StringIO
from operator import itemgetter


class BlockBackendCorruptedException(Exception):
    """
    Exception raised by BlockBackend when the internal metadata
    structure reports a corrupted data (CRC mismatch).
    """
    pass


class StorageBackend(object):
    """
    The base template for Storage backend classes.
    """

    def __init__(self):
        # the atomic block size of the underlying storage
        self._blocksize = 512

    def connect(self):
        """Initialize the storage."""
        raise NotImplementedError()

    def disconnect(self):
        """Close the storage."""
        raise NotImplementedError()

    def filename(self, service):
        """
        Return a tuple with the filename to open and bytes to skip
        to get to the metadata structures.
        """
        raise NotImplementedError()

    @property
    def blocksize(self):
        return self._blocksize

    def create(self, service_map):
        """
        Reinitialize the storage backend according to the service_map.
        Key represents service name and value contains the size of the
        required block in Bytes.
        """
        raise NotImplementedError()


class FilesystemBackend(StorageBackend):
    """
    Backend for all filesystem based access structures. This
    includes VDSM's LVM block devices as they are accessed using symlinks
    in the same structure that VDSM uses for NFS based storage domains.
    """
    def __init__(self, sd_uuid, dom_type):
        super(FilesystemBackend, self).__init__()
        self._sd_uuid = sd_uuid
        self._dom_type = dom_type
        self._lv_based = False
        self._storage_path = None

    def filename(self, service):
        fname = os.path.join(self._storage_path, service)
        return (fname, 0)

    def get_domain_path(self, sd_uuid, dom_type):
        """
        Return path of storage domain holding engine vm
        """
        parent = constants.SD_MOUNT_PARENT
        if dom_type == 'glusterfs':
            parent = os.path.join(parent, 'glusterSD')

        for dname in os.listdir(parent):
            path = os.path.join(parent, dname, sd_uuid)
            if os.access(path, os.F_OK):
                if dname == "blockSD":
                    self._lv_based = True
                return path
        raise Exception("path to storage domain {0} not found in {1}"
                        .format(sd_uuid, parent))

    def connect(self):
        self._lv_based = False
        self._storage_path = os.path.join(self.get_domain_path(self._sd_uuid,
                                                               self._dom_type),
                                          constants.SD_METADATA_DIR)
        util.mkdir_recursive(self._storage_path)

        if not self._lv_based:
            return

        # create LV symlinks
        uuid = self._sd_uuid
        for lv in os.listdir(os.path.join("/dev", uuid)):
            # skip all LVs that do not have proper name
            if not lv.startswith(constants.SD_METADATA_DIR + "-"):
                continue

            # strip the prefix and use the rest as symlink name
            service = lv.split(constants.SD_METADATA_DIR + "-", 1)[-1]
            os.symlink(os.path.join("/dev", uuid, lv),
                       os.path.join(self._storage_path, service))

    def disconnect(self):
        pass

    def lvcreate(self, vg_uuid, lv_name, size_bytes, popen=subprocess.Popen):
        """
        Call lvm lvcreate and ask it to create a Logical Volume in the
        Storage Domain's Volume Group. It should be named lv_name
        and be big enough to fit size_bytes into it.
        """
        lvc = popen(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    args=["lvm", "lvcreate", "-L", str(size_bytes)+"B",
                          "-n", lv_name, vg_uuid])
        lvc.wait()

    def create(self, service_map):
        for service, size in service_map.iteritems():
            service_path = os.path.join(self._storage_path, service)
            if self._lv_based:
                lvname = "-".join([constants.SD_METADATA_DIR, service])
                self.lvcreate(self._sd_uuid, lvname, size)
            else:
                # file based storage
                with open(service_path, "w") as f:
                    # create an empty file, possibly utilizing
                    # sparse files if size was provided
                    if size:
                        f.seek(size - 1)
                        f.write(0)

        # reconnect so all links are refreshed
        self.disconnect()
        self.connect()


class BlockBackend(StorageBackend):
    """
    This uses a pure block device to expose the data. It requires device
    mapper support to explode the single device to couple of virtual files.

    This is supposed to be used for devices that are not managed by VDSM
    or do not use LVM.

    The structure is described using a table that starts at block 0
    of the block device.

    The format of that block is:

    <the next chained block:64bit> - 0 means this is the last block
    <service name used length: 1 Byte>
    <service name: 63 Bytes>
    <data area start block:64 bit>
    <data area block length:64 bit>
    ... data area records can be repeated if they fit into one block
    ... if there is need for more data area records, one of the chained
    ... blocks can add them to the same service name
    128bit (16B) of 0s as a sentinel
    32bit CRC32

    This information is converted to Device Mapper table and used to create
    the logical device files.
    """

    # Binary format specifications, all in network byte order
    # The name supports only 63 characters
    BlockInfo = namedtuple("BlockInfo", ("next", "name", "pieces", "valid"))
    BlockStructHeader = struct.Struct("!Q64p")
    BlockStructData = struct.Struct("!QQ")
    BlockCRC = struct.Struct("!L")

    def __init__(self, block_dev_name, dm_prefix):
        super(BlockBackend, self).__init__()
        self._block_dev_name = block_dev_name
        self._dm_prefix = dm_prefix
        self._services = {}

    def parse_meta_block(self, block):
        """
        Parse one info block from the raw byte representation
        to namedtuple BlockInfo.
        """
        next_block, name = self.BlockStructHeader.unpack_from(block, 0)
        pieces = []
        seek = self.BlockStructHeader.size
        while True:
            start, size = self.BlockStructData.unpack_from(block, seek)
            seek += self.BlockStructData.size
            # end of blocks section sentinel
            if start == size and size == 0:
                break
            pieces.append((start, size))
        crc = zlib.crc32(block[:seek]) & 0xffffffff
        # the comma is important, unpack_from returns a single element tuple
        expected_crc, = self.BlockCRC.unpack_from(block, seek)

        return self.BlockInfo._make((next_block, name,
                                     tuple(pieces), crc == expected_crc))

    def get_services(self, block_device_fo):
        """
        Read all the info blocks from a block device and
        assemble the services dictionary mapping
        service name to a list of (data block start, size)
        tuples.
        """
        offset = block_device_fo.tell()
        services = {}
        while True:
            block = block_device_fo.read(self.blocksize)
            parsed = self.parse_meta_block(block)
            if not parsed.valid:
                raise BlockBackendCorruptedException(
                    "CRC for block ending at %d does not match data!"
                    % block_device_fo.tell())
            services.setdefault(parsed.name, [])
            services[parsed.name].extend(parsed.pieces)
            if parsed.next == 0:
                break
            else:
                block_device_fo.seek(offset + parsed.next * self.blocksize, 0)
        return services

    def dm_name(self, service):
        return os.path.join(self._dm_prefix, service)

    def compute_dm_table(self, pieces):
        """
        Take a list of tuples in the form of (start, size) and
        create the string representation of device mapper table
        that can be used in dmsetup.
        """
        table = []
        log_start = 0
        for start, size in pieces:
            table.append("%d %d linear %s %d"
                         % (log_start, size, self._block_dev_name, start))
            log_start += size
        return "\n".join(table)

    def connect(self):
        with open(self._block_dev_name, "r") as bd:
            self._services = self.get_services(bd)

        for name, pieces in self._services:
            table = self.compute_dm_table(pieces)
            self.dmcreate(name, table)

    def disconnect(self):
        for name in self._services:
            self.dmremove(name)

    def dmcreate(self, name, table, popen=subprocess.Popen):
        """
        Call dmsetup create <name> and pass it the table.
        """
        dm = popen(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,
                   args=["dmsetup", "create", name])
        print "Table for %s" % name
        print table
        print

        dm.communicate(table)

    def dmremove(self, name, popen=subprocess.Popen):
        """
        Call dmsetup remove to destroy the device.
        """
        dm = popen(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE,
                   args=["dmsetup", "remove", name])
        stdout, stderr = dm.communicate()

    def filename(self, service):
        if service not in self._services:
            return None
        else:
            return os.path.join("/dev/mapper", self.dm_name(service)), 0

    def create_info_blocks(self, service_map):
        def bc(size):
            """
            Return the number of blocks needed to accommodate size
            number of Bytes.
            """
            return int(math.ceil(size / float(self._blocksize)))

        # first len(service_map) blocks will contain
        # the information about services and their data locations
        data_start = len(service_map)
        info_blocks = []

        # Linearize the list, put smaller services before bigger ones
        service_list = service_map.items()
        service_list.sort(key=itemgetter(1))

        # create list of next ids that starts with 1, goes to the last
        # index (size - 1) and then ends with 0
        next_links = range(1, data_start) + [0]
        for next_id, (service, size) in zip(next_links, service_list):
            block_len = bc(size)
            raw_data = StringIO()
            raw_data.write(self.BlockStructHeader.pack(next_id, service))
            raw_data.write(self.BlockStructData.pack(data_start, block_len))
            raw_data.write(self.BlockStructData.pack(0, 0))
            crc = zlib.crc32(raw_data.getvalue()) & 0xffffffff
            raw_data.write(self.BlockCRC.pack(crc))
            info_blocks.append(raw_data.getvalue())
            data_start += block_len

        return info_blocks

    def create(self, service_map):
        info_blocks = self.create_info_blocks(service_map)
        with open(self._block_dev_name, "w") as dev:
            for idx, b in enumerate(info_blocks):
                dev.seek(idx * self._blocksize)
                dev.write(b)

        self.disconnect()
        self.connect()
