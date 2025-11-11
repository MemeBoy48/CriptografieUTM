from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

# Parametrii
p = 3231700607131100730015351347782516336248805713348907517458843413926980683413621000279205636264016468545855635793533081692882902308057347262527355474246124574102620252791657297286270630032526342821314576693141422365422094111134862999165747826803423055308634905063555771221918789033272956969612974385624174123623722519734640269185579776797682301462539793305801522685873076119753243646747585546071504389684494036613049769781285429595865959756705128385213278446852292550456827287911372009893187395914337417583782600027803497319855206060753323412260325468408812003110590748428100399496695611969695624862903233807283912703
g = 2

print("Schimb de chei ULTIMA SARCINA\n")

# David alege i
i = random.randint(2, p-2)
print(f"David alege cheia privată i = {i}")
input()

k_E = pow(g, i, p)
print(f"David calculeaz chiaia publica k_E = g^i mod p:")
print(f"k_E = {k_E}\n")


input()
# Artiom alege d
d = random.randint(2, p-2)
print(f"\nArtiom alege cheia privata d = {d}")

beta = pow(g, d, p)
print(f"Artiom calculeaza cheia publica b = g^d mod p:")
print(f"b = {beta}\n")
input()

# David calculează k_M
k_M = pow(beta, i, p)
print(f"\nDavid calculeaza cheia de mascare(cheia partajata):")
print(f"k_M = b^i mod p = {k_M}\n")
input()

# Artiom calculeaza k_M
k_M_Artiom = pow(k_E, d, p)
print(f"\nArtiom calculeaza cheia de mascare(cheia partajata):")
print(f"k_M = k_E^d mod p = {k_M_Artiom}\n")

print(f"Verificare: k_M este identică = {k_M == k_M_Artiom}\n")

input()

# Cheie AES-256 (32 bytes)
# Convertim k_M într-un numar de bytes primi 32 bytes
k_M_bytes = k_M.to_bytes((k_M.bit_length() + 7) // 8, byteorder='big')# 7 imparte la 8 pentru a rotunji in sus
aes_key = k_M_bytes[:32]
print("\nCriptare cu AES-256\n")

# Criptare
message = "Avram Alexandru"
print(f"Mesaj original: {message}")

input()
cipher = AES.new(aes_key, AES.MODE_CBC)
iv = cipher.iv
ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
print(f"Text criptat: {ciphertext.hex()}\n")

input()
# Decriptare
cipher2 = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted = unpad(cipher2.decrypt(ciphertext), AES.block_size).decode()

print(f"Mesaj decriptat: {decrypted}")
print(f"YAYAYAYAYAY! daca comparam rezultatul e {message == decrypted}")
