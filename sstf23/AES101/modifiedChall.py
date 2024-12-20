from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

flag = b"FAKE FLAG"
key = b"AAAABBBBCCCCDDDD"
while True:
	try:
		iv = bytes.fromhex(input("IV(hex): "))
		if len(iv) != 16:
			raise Exception
		msg = bytes.fromhex(input("CipherText(hex): "))
		if len(msg) % 16:
			raise Exception
	except:
		print("Wrong input.")
		continue

	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(msg)
	try:
		plaintext = unpad(plaintext, 16)
	except:
		print("Try again.")
		continue

	if plaintext == b"CBC Magic!":
		print(flag)
		break
	else:
		print("Wrong CipherText.")
