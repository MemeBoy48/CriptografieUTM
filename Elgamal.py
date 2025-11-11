import random
from Crypto.Util.number import long_to_bytes, bytes_to_long

p = 3231700607131100730015351347782516336248805713348907517458843413926980683413621000279205636264016468545855635793533081692882902308057347262527355474246124574102620252791657297286270630032526342821314576693141422365422094111134862999165747826803423055308634905063555771221918789033272956969612974385624174123623722519734640269185579776797682301462539793305801522685873076119753243646747585546071504389684494036613049769781285429595865959756705128385213278446852292550456827287911372009893187395914337417583782600027803497319855206060753323412260325468408812003110590748428100399496695611969695624862903233807283912703
g = 2

m = "Avram Alexandru"
print(f"Mesajul original: {m}")
print(f"p (2048 biti)")
print(f"g = {g}")

input()
# Convertim mesajul in numar
m_numeric = bytes_to_long(m.encode('utf-8'))
print(f"\nMesajul ca numar: {m_numeric}")

input()
# Cheia privata a lui David a apartine {1,2,...,p-1}
print("David")
a = random.randint(2, p-2)
print(f"\nCheia privata a lui David (a): {a}")

input()
# Cheia publica a lui David: A = g^a mod p
A = pow(g, a, p)
print(f"Cheia publica a lui David (A = g^a mod p): {A}")

input()
# Cheia privata a lui Artiom: b apartine {1,2,...,p-1}
print("Artiom")
b = random.randint(2, p-2)
print(f"\nCheia privata a lui Artiom (b): {b}")
# Cheia publica a lui Artiom: B = g^b mod p
B = pow(g, b, p)
print(f"Cheia publica a lui Artiom (B = g^b mod p): {B}")

input()
k_AB_david = pow(B, a, p)
print(f"\nDavid calculeaza: k_AB = B^a mod p = {k_AB_david}")

k_AB_art = pow(A, b, p)
print(f"Artiom calculeaza: k_AB = A^b mod p = {k_AB_art}")

input()
# Criptarea cu cheia publica
print("\n" + "="*80)
print("CRIPTARE")


input()
# Alegem un numar random k (efemer)
k_random = random.randint(2, p-2)
print(f"\nNumar random k (efemer): {k_random}")

input()
# Calculam c1 = g^k mod p
c1 = pow(g, k_random, p)
print(f"c1 = g^k mod p = {c1}")


# c2 = m * A^k mod p
print("Folosim cheia publica a lui David (A)")
c2 = (m_numeric * pow(A, k_random, p)) % p
print(f"c2 = m * A^k mod p = {c2}")

print(f"\nTextul criptat (c1, c2): ({c1}, {c2})")

# DECRIPTARE cu cheia privata
print("\n" + "="*80)
print("DECRIPTARE")
input()

# Pentru a decripta David foloseste privata
# m = c2 * (c1^a)^(-1) mod p
# Calculam s = c1^a mod p
s = pow(c1, a, p)
print(f"\ns = c1^a mod p = {s}")
# Calculam inversul modular al lui s
s_inv = pow(s, -1, p)
print(f"s^(-1) mod p = {s_inv}")

# Decrioptam mesajul in biti
m_decrypted_numeric = (c2 * s_inv) % p
print(f"m decriptat (numar) = {m_decrypted_numeric}")
input()
# Convertim inapoi in text
m_decrypted = long_to_bytes(m_decrypted_numeric).decode('utf-8')
print(f"m decriptat (text) = {m_decrypted}")


print("\n" + "="*80)
print("VERIFICARE bog spasii")
input()
# Sper ca e correct
print("Verificam sa vedem cat e de corect")
if m == m_decrypted:
    print("YAY, mesajul decriptat este la fel cu mesajul original")
    print(f"  Original:  {m}")
    print(f"  Decriptat: {m_decrypted}")
else:
    print("Ceva am facut gresit mesajele nu aceleasi")
    print(f"  Original:  {m}")
    print(f"  Decriptat: {m_decrypted}")
