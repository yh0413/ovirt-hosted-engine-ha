import unittest
import cStringIO as StringIO
import struct
import zlib

from .storage_backends import BlockBackend


class StorageBackendTests(unittest.TestCase):

    def test_single_bad_block_decode(self):
        raw = struct.pack("!Q64pQQQQQQL",
                          1, "test",
                          1, 100,
                          102, 100,
                          0, 0,
                          0)
        b = BlockBackend("/dev/null", "test-1")
        block = b.parse_meta_block(raw)
        self.assertEqual(block, BlockBackend.BlockInfo(
            1, "test", ((1, 100), (102, 100)), False))

    def test_service_creation(self):
        b = BlockBackend("/dev/null", "test-1")
        blocks = b.create_info_blocks({"test1": 300,
                                       "test2": 512,
                                       "test3": 1024*1024*50})

        self.assertEqual(3, len(blocks))

        test1 = struct.pack("!Q64pQQQQ",
                            1, "test1",
                            3, 1,
                            0, 0)
        test1crc = struct.pack("!L", zlib.crc32(test1) & 0xffffffff)
        test2 = struct.pack("!Q64pQQQQ",
                            2, "test2",
                            4, 1,
                            0, 0)
        test2crc = struct.pack("!L", zlib.crc32(test2) & 0xffffffff)
        test3 = struct.pack("!Q64pQQQQ",
                            0, "test3",
                            5, 102400,
                            0, 0)
        test3crc = struct.pack("!L", zlib.crc32(test3) & 0xffffffff)

        expected = [
            test1 + test1crc,
            test2 + test2crc,
            test3 + test3crc
        ]

        self.assertEqual(expected, blocks)

    def test_single_good_block_decode(self):
        raw = struct.pack("!Q64pQQQQQQ",
                          1, "test",
                          1, 100,
                          102, 100,
                          0, 0)
        rawcrc = struct.pack("!L", zlib.crc32(raw) & 0xffffffff)
        b = BlockBackend("/dev/null", "test-1")
        block = b.parse_meta_block(raw+rawcrc)
        self.assertEqual(block, BlockBackend.BlockInfo(
            1, "test", ((1, 100), (102, 100)), True))

    def test_dm_table(self):
        block = BlockBackend.BlockInfo(1, "test", ((1, 100), (102, 100)), True)
        b = BlockBackend("/dev/null", "test-1")
        table = b.compute_dm_table(block.pieces)
        expected = ("0 100 linear /dev/null 1\n"
                    "100 100 linear /dev/null 102")
        self.assertEqual(expected, table)

    def test_get_services(self):
        raw1 = struct.pack("!Q64pQQQQQQ",
                           1, "test",
                           1, 100,
                           102, 100,
                           0, 0)
        raw1crc = struct.pack("!L", zlib.crc32(raw1) & 0xffffffff)

        raw2 = struct.pack("!Q64pQQQQQQ",
                           0, "test2",
                           2, 200,
                           202, 200,
                           0, 0)
        raw2crc = struct.pack("!L", zlib.crc32(raw2) & 0xffffffff)

        b = BlockBackend("/dev/null", "test-1")
        blockdev = StringIO.StringIO()
        blockdev.write(raw1)
        blockdev.write(raw1crc)
        blockdev.seek(b.blocksize)
        blockdev.write(raw2)
        blockdev.write(raw2crc)
        blockdev.seek(0)
        expected = {'test': [(1, 100), (102, 100)],
                    'test2': [(2, 200), (202, 200)]}
        services = b.get_services(blockdev)
        self.assertEqual(expected, services)
