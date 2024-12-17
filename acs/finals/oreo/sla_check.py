#!/usr/bin/env python3

from pwn import *
import time

context.clear(arch='amd64')

MENU = b"> "
EXTRA = b": "
PATCHED = 0
ONLINE = 1
OFFLINE = 2


def menu(p, num):
    p.sendlineafter(MENU, str(num).encode('ascii'), timeout=2)

def send_payload_iter(p, payload, start_time):
    while True:
        time.sleep(0.98)
        p.sendlineafter(EXTRA, payload, timeout=2)
        p.readuntil(b"The answer is [", timeout=2)
        answer = p.recvn(1, timeout=2)
        if not answer:
            return 0
        if (answer == b'1'):
            return 1
        if (time.time() - start_time >= 30):
            return 2

def exploit(p):
    start_time = time.time()
    
    # Check Buffer Overflow
    menu(p, 1)
    p.sendlineafter(EXTRA, b"ORE", timeout=2)
    
    menu(p, 3)
    result = send_payload_iter(p, b"A"*0x18+b"B", start_time)
    if not result:
        return 0
    else:
        if result == 2:
            return 2
    
    p.sendlineafter(EXTRA, b"quit", timeout=2)
    msg = p.recvline(timeout=2)
    if msg[:-1] == b"*** stack smashing detected ***: terminated":
        return 1

    # Check FSB
    menu(p, 1)
    leak_oper = b"%p"*14
    p.sendlineafter(EXTRA, leak_oper, timeout=2)
    menu(p, 2)
    p.readuntil(b"[ERROR] ", timeout=2)
    stack = p.readuntil(b"=", timeout=2)[:-1]
    if stack[:2] != b'%p':
        return 1

    return 0

def view_check(p, oreo, check_o, check_re, check_money):
    menu(p, 5)
    p.readuntil(EXTRA, timeout=2)
    oper = p.readline(timeout=2)[:-1]
    p.readuntil(EXTRA, timeout=2)
    remain_o = p.readline(timeout=2)[:-1]
    p.readuntil(EXTRA, timeout=2)
    remain_re = p.readline(timeout=2)[:-1]
    p.readuntil(EXTRA, timeout=2)
    money = p.readuntil(b"$", timeout=2)[:-1]

    if oper == oreo:
        if remain_o == check_o:
            if remain_re == check_re:
                if money == check_money:
                    return 1
                else:
                    return 0
            else:
                return 0
        else:
            return 0
    else:
        return 0


def online(p):
    # 1. operation
    menu(p, 1)
    oreo = b"OREO&OREO&OREO&OREO&OREO&OREO"
    p.sendlineafter(EXTRA, oreo, timeout=2)
    if not view_check(p, oreo, b'20', b'10', b'0'):
        return 0

    # 2. oreo
    menu(p, 1)
    oreo = b"RErEO&o"
    p.sendlineafter(EXTRA, oreo, timeout=2)

    menu(p, 2)
    re1 = p.readline(timeout=2)
    p.readline(timeout=2)
    re2 = p.readline(timeout=2)
    p.readline(timeout=2)
    o1 = p.readline(timeout=2)
    p.readline(timeout=2)
    n1 = p.readline(timeout=2)
    n2 = p.readline(timeout=2)
    p.readline(timeout=2)
    o2 = p.readline(timeout=2)
    p.readline(timeout=2)

    if re1 == re2 == b'\x1b[37;47m....................\x1b[m\n':
        if o1 == o2 == b'\x1b[30;40m....................\x1b[m\n':
            if n1 == n2 == b'\n':
                pass
            else:
                return 0
        else:
            return 0
    else:
        return 0

    # 3. mine
    menu(p, 3)
    answer = b"reoreo"

    while True:
        p.sendlineafter(EXTRA, answer, timeout=2)
        result = p.readline(timeout=2)
        if not result:
            return 0
        time.sleep(0.98)
        if result == b'your answer is [2]\n' or result == b'correct! + 10$\n':
            break

    p.sendlineafter(EXTRA, b"quit", timeout=2)
    if not view_check(p, oreo, b'18', b'8', b'10'):
        return 0

    # 4. market
    menu(p, 4)
    p.sendlineafter(EXTRA, b'4', timeout=2)
    if not view_check(p, oreo, b'26', b'12', b'6'):
        return 0

    # 6. exit
    menu(p, 6)
    return 1


def check_status(ip):
    # 0 - PATCHED / 1 - ONLINE / 2 - OFFLINE
    status = OFFLINE

    #p = process("../challenge/oreo")
    #p = remote(ip, 12345)
    p = process("./oreo_patched")
    on = online(p)
    if on == 1:  # service good
        status = ONLINE
        p.close()
        while True:
            #p = process("../challenge/oreo")
            #p = remote(ip, 12345)
            p = process("./oreo_patched")
            ex = exploit(p)
            p.close()
            if ex != 2:
                break
        if ex == 0:  # exploit not work
            status = PATCHED
    return status


if __name__ == "__main__":
    sla = check_status('127.0.0.1')
    print(sla)
