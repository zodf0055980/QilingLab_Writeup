import sys
from qiling import *
from qiling.const import QL_VERBOSE
from qiling.os.mapper import QlFsMappedObject
import struct

sys.path.append("..")

class Fake_urandom(QlFsMappedObject):
    def read(self, size):
        if(size > 1):
            return b"\x01" * size
        else:
            return b"\x02"
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0

class Fake_cmdline(QlFsMappedObject):

    def read(self, size):
        return b"qilinglab" # type should byte byte, string will error = =
    def fstat(self): # syscall fstat will ignore it if return -1
        return -1
    def close(self):
        return 0

def my_syscall_uname(ql, write_buf, *args, **kw):
    buf = b'QilingOS\x00' # sysname
    ql.mem.write(write_buf, buf)

    buf = b'30000'.ljust(65, b'\x00') # important!! If not set will `FATAL: kernel too old`
    ql.mem.write(write_buf+65*2, buf)
    buf = b'ChallengeStart'.ljust(65, b'\x00') # version
    ql.mem.write(write_buf+65*3, buf)
    regreturn = 0
    return regreturn


def my_syscall_getrandom(ql, write_buf, write_buf_size, flag , *args, **kw):
    buf = b"\x01" * write_buf_size
    ql.mem.write(write_buf, buf)
    regreturn = 0
    return regreturn

def hook_cmp(ql):
    ql.reg.w0 = 1
    return

def hook_rand(ql, *args, **kw):
    ql.reg.w0 = 0
    return

def hook_cmp2(ql):
    ql.reg.w0 = 0
    return

def hook_sleeptime(ql):
    ql.reg.w0 = 0
    return

def hook_tolower(ql):
    return
    
def find_and_patch(ql, *args, **kw):
    MAGIC = 0x3DFCD6EA00000539
    magic_addrs = ql.mem.search(ql.pack64(MAGIC)) 

    # check_all_magic
    for magic_addr in magic_addrs:
        # Dump and unpack the candidate structure
        malloc1_addr = magic_addr - 8
        malloc1_data = ql.mem.read(malloc1_addr, 24)
        # unpack three unsigned long
        string_addr, _ , check_addr = struct.unpack('QQQ', malloc1_data)

        # check string data        
        if ql.mem.string(string_addr) == "Random data":
            ql.mem.write(check_addr, b"\x01")
            break
    return

def midr_el1_hook(ql, address, size):  

    # 001013ec 00 00 38 d5     mrs        x0,midr_el1

    if ql.mem.read(address, size) == b"\x00\x00\x38\xD5":
        # if any code is mrs        x0,midr_el1
        # Write the expected value to x0
        ql.reg.x0 = 0x1337 << 0x10
        # Go to next instruction
        ql.reg.arch_pc += 4
    # important !! Maybe hook library
    # see : https://joansivion.github.io/qilinglabs/
    return

if __name__ == "__main__":
    ql = Qiling(["qilinglab-aarch64"], "rootfs/arm64_linux"
    ,verbose=QL_VERBOSE.OFF
    )

    # challenge 1

    # need to align the memory offset and address for mapping.
    # size at least a multiple of 4096 for alignment
    ql.mem.map(0x1337//4096*4096, 4096)
    ql.mem.write(0x1337,ql.pack16(1337) )

    # challenge 2
    ql.set_syscall("uname", my_syscall_uname)

    # challenge 3
    ql.add_fs_mapper('/dev/urandom', Fake_urandom())
    ql.set_syscall("getrandom", my_syscall_getrandom)

    # challenge 4

    base_addr = ql.mem.get_lib_base(ql.path) # get pie_base addr

    # 00100fd8 e0 1b 40 b9     ldr        w0,[sp, #local_8]
    # 00100fdc e1 1f 40 b9     ldr        w1,[sp, #local_4]
    # 00100fe0 3f 00 00 6b     cmp        w1,w0

    ql.hook_address(hook_cmp, base_addr + 0xfe0)

    # callenge 5
    ql.set_api("rand", hook_rand)

    # challenge 6
    ql.hook_address(hook_sleeptime, base_addr + 0x001118)

    # challenge 7
    ql.hook_address(hook_cmp, base_addr + 0x1154)

    # challenge 8

    # 001011d0 e0 17 40 f9     ldr        magic_string,[sp, #local_8]
    # 001011d4 e1 0f 40 f9     ldr        x1,[sp, #local_18]
    # 001011d8 01 08 00 f9     str        x1,[magic_string, #0x10]
    # 001011dc 1f 20 03 d5     nop        <-    hook
    # 001011e0 fd 7b c3 a8     ldp        x29=>local_30,x30,[sp], #0x30
    # 001011e4 c0 03 5f d6     ret
    ql.hook_address(find_and_patch, base_addr + 0x011dc)


    # challenge 9
    ql.set_api("tolower", hook_tolower)

    # challenge 10
    ql.add_fs_mapper('/proc/self/cmdline', Fake_cmdline())

    # challenge 11
    ql.hook_code(midr_el1_hook)

    # end and run
    ql.run()
