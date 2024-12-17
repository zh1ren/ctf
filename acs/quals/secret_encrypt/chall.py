from Crypto.Util.number import getPrime

def secret():
    global secret1,secret2,secret3,secret4
    result = 0
    temp_secret1 = secret1
    temp_secret3 = secret3
    while temp_secret3 > 0: # while still got a 1 available
        # if odd. result only changes if odd
        # if got 4 1 bits, then results is just 4*s1 % s2
        if (temp_secret3 & 1) == 1:
            result = (result + temp_secret1) % secret2

        temp_secret1 = (temp_secret1 * 2) % secret2
        temp_secret3 >>= 1 # go to next bit
    secret1 = (result + secret4) % secret2
    return secret1

bits = 1024
p_rsa = getPrime(bits)
q_rsa = getPrime(bits)
n = p_rsa * q_rsa
e = 65537

FLAG = "***********redacted*************"
message_int = int.from_bytes(FLAG.encode(), 'big')
encrypted_message = pow(message_int, e, n)


secret1 = p_rsa
secret2 = 2 ** 1024 # 1025 bits
secret3 = getPrime(1024)   
secret4 = getPrime(1024) 
     

out = [secret() for _ in range(3)]

print(f"n={n}")
print(f"enc= {encrypted_message}")
print(f"secret_out={out}")
