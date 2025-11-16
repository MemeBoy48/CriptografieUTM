import random
import struct
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sys
# Ssunt prea mari numerele, sad:(
sys.set_int_max_str_digits(10000)
# ============================================================================
# MD5 HASH IMPLEMENTATION 
# ============================================================================

def md5(data):
    """
    MD5 este o functie hash criptografica care genereaza o iesire de 128 biti
    pentru orice mesaj de intrare. Algoritmul este deprecated pentru securitate,
    dar este folositpentru scopuri educationale.
    """
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Constante MD5 - aceste sunt valorile T[i] = int(2^32 * abs(sin(i)))
    T = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]
    
    # Functii auxiliare MD5
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & z) | (y & ~z)
    def H(x, y, z): return x ^ y ^ z
    def I(x, y, z): return y ^ (x | ~z)
    
    def left_rotate(value, amount):
        value &= 0xffffffff
        return ((value << amount) | (value >> (32 - amount))) & 0xffffffff
    
    # Valorile initiale ale hash-ului (constante MD5)
    A = 0x67452301
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476
    
    # Padding
    msg = bytearray(data)
    msg_len = len(data)
    msg.append(0x80)
    
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    
    msg += struct.pack('<Q', msg_len * 8)
    
    # Procesare blocuri
    for offset in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[offset:offset + 64]))
        
        AA, BB, CC, DD = A, B, C, D
        
        # 64 de runde
        for i in range(64):
            if i < 16:
                f = F(B, C, D)
                g = i
                s = [7, 12, 17, 22][i % 4]
            elif i < 32:
                f = G(B, C, D)
                g = (5 * i + 1) % 16
                s = [5, 9, 14, 20][(i - 16) % 4]
            elif i < 48:
                f = H(B, C, D)
                g = (3 * i + 5) % 16
                s = [4, 11, 16, 23][(i - 32) % 4]
            else:
                f = I(B, C, D)
                g = (7 * i) % 16
                s = [6, 10, 15, 21][(i - 48) % 4]
            
            temp = (A + f + T[i] + X[g]) & 0xffffffff
            temp = left_rotate(temp, s)
            temp = (temp + B) & 0xffffffff
            
            A, B, C, D = D, temp, B, C
        
        A = (A + AA) & 0xffffffff
        B = (B + BB) & 0xffffffff
        C = (C + CC) & 0xffffffff
        D = (D + DD) & 0xffffffff
    
    return struct.pack('<4I', A, B, C, D)


# ============================================================================
# SEMNARE DIGITALA ELGAMAL CU MD5
# ============================================================================

def elgamal_sign(message, p, g, x):
    """
    Semneaza un mesaj folosind semnatura ElGamal cu hash MD5.
    
    Parametri:
    - message: mesajul de semnat
    - p: numar prim mare
    - g: generator al grupului
    - x: cheia privata
    
    Returneaza:
    - (r, s): semnatura ElGamal
    - hash_value: hash MD5 al mesajului
    """
    # Calculam hash MD5 al mesajului
    hash_value = md5(message.encode('utf-8') if isinstance(message, str) else message)
    
    # Convertim hash-ul in numar intreg
    h = int.from_bytes(hash_value, byteorder='big')
    
    # Alegem un k random, sa fie invers modular sa existe
    while True:
        k = random.randint(2, p - 2)
        if pow(k, p - 2, p) != 1:  # Verificam ca exista invers
            break
    
    # Calculam r = g^k mod p
    r = pow(g, k, p)
    
    # Calculam k_inv = k^(-1) mod (p-1)
    k_inv = pow(k, -1, p - 1)
    
    # Calculam s = k_inv * (h - x*r) mod (p-1)
    s = (k_inv * (h - x * r)) % (p - 1)
    
    return (r, s), hash_value


def elgamal_verify(message, signature, p, g, y):
    """
    Verifica o semnatura ElGamal cu hash MD5.
    
    Parametri:
    - message: mesajul semnat
    - signature: (r, s) - semnatura ElGamal
    - p: numar prim mare
    - g: generator al grupului
    - y: cheia publica (y = g^x mod p)
    
    Returneaza:
    - True/False: daca semnatura este valida
    - hash_value: hash MD5 al mesajului
    """
    r, s = signature
    
    # Calculam hash MD5 al mesajului
    hash_value = md5(message.encode('utf-8') if isinstance(message, str) else message)
    
    # Convertim hash-ul in numar intreg
    h = int.from_bytes(hash_value, byteorder='big')
    
    # Verificam: g^h ≡ y^r * r^s (mod p)
    # Calculam lhs = g^h mod p
    lhs = pow(g, h, p)
    
    # Calculam rhs = (y^r * r^s) mod p
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    
    is_valid = lhs == rhs
    
    return is_valid, hash_value


p = 3231700607131100730015351347782516336248805713348907517458843413926980683413621000279205636264016468545855635793533081692882902308057347262527355474246124574102620252791657297286270630032526342821314576693141422365422094111134862999165747826803423055308634905063555771221918789033272956969612974385624174123623722519734640269185579776797682301462539793305801522685873076119753243646747585546071504389684494036613049769781285429595865959756705128385213278446852292550456827287911372009893187395914337417583782600027803497319855206060753323412260325468408812003110590748428100399496695611969695624862903233807283912703
g = 2

m = "Vigenère was born in the village of Saint-Pourcain, " \
"about halfway between Paris and Marseilles, on April 5, 1523. " \
"At 24, he entered the service of the Duke of Nevers, to whose " \
"house he remained attached the rest of his life, except for periods " \
"at court and as a diplomat. In 1549, at 26, he went to Rome on a " \
"two-year diplomatic mission.It was here that he was first thrown " \
"into contact with cryptology, and he seems to have steeped himself " \
"in it. He read the books of Trithemius, Belaso, and other writers, and " \
"the unpublished manuscript of Alberti. He evidently conversed with the " \
"experts of the Papal Curia, for he tells anecdotes that he could have " \
"heard only in the shoptalk of these cryptologists.At 47, Vigenère quit " \
"the court, turned over his annuity of 1,000 livres a year to the poor of " \
"Paris, married the much younger Marie Vare, and devoted himself to his writin. " \
"His Traicté des Chiffres, which was written in 1585 despite the distraction of a " \
"year-old baby daughter, appeared elegantly rubricated in 1586 and was reprinted " \
"the following year. His autokey system used the plaintext as the key. " \
"It provided a priming key. This consisted of a single letter, known to " \
"both encipherer and decipherer, with which the decipherer could decipher " \
"the first cryptogram letter and so get a start on his work. With this," \
" he would get the first plaintext letter, then use this as the key to decipher " \
"the second cryptogram letter, use that plaintext as the key to decipher the " \
"third cryptogram letter, and so on.The system works well and affords fair " \
"guarantees of security; it has been embodied in a number of modern cipher machines. " \
"In spite of Vigenère's clear exposition of his technique, it was entirely " \
"forgotten and only entered the stream of cryptology late in the 19th century after " \
"it had been reinvented. Writers on cryptology then added insult to injury by degrading Vigenère's system " \
"into one much more elementary.The cipher now universally called the Vigenère employs only standard " \
"alphabets and a short repeating keyword—a system far more susceptible to solution than Vigenère's autokey. " \
"Its tableau consists of a modern tabula recta: 26 standard horizontal alphabets, each slid one space to the " \
"left of the one above. These are the cipher alphabets. A normal alphabet for the plaintext stands at the top." \
"Another normal alphabet, which merely repeats the initial letters of the horizontal ciphertext alphabets, runs down " \
"the left side. This is the key alphabet.Both correspondents must know the keyword. The encipherer repeats this above " \
"the plaintext letters until each one has a key letter. He seeks the plaintext letter in the top alphabet and the key letter " \
"in the side alphabet. Then he traces down from the top and in from the side. The ciphertext letter stands at the intersection " \
"of the column and the row. The encipherer repeats this process with all the letters of the plaintext. To decipher, the clerk " \
"begins with the key letter, runs in along the ciphertext alphabet until he strikes the cipher letter, then follows the column " \
"of letters upward until he emerges at the plaintext letter at the top.Polyalphabetic ciphers were, when used with mixed alphabets " \
"and without word divisions, unbreakable to the cryptanalysts of the Renaissance. Why, then, did the nomenclator reign " \
"supreme for 300 years? Why did cryptographers not use the polyalphabetic system instead?"
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
# Criptarea cu cheia publica - criptam HASH-ul, nu mesajul intreg
print("\n" + "="*80)
print("CRIPTARE CU HASH MD5")
print("="*80)

input()
# Calculam hash MD5 al mesajului lung
print("\nCalculam hash MD5 al mesajului:")
print(f"Mesajul: {m[:60]}...")
hash_md5_msg = md5(m.encode('utf-8'))
print(f"\nHash MD5: {hash_md5_msg.hex()}")
print(f"Lungime: {len(hash_md5_msg)} octeti (128 biti)")

# Convertim hash-ul in numar pentru criptare
hash_numeric = int.from_bytes(hash_md5_msg, byteorder='big')
print(f"Hash ca numar: {hash_numeric}")


input()
# Alegem un numar random k (efemer)
k_random = random.randint(2, p-2)
print(f"\nNumar random k (efemer): {k_random}")

input()
# Calculam c1 = g^k mod p
c1 = pow(g, k_random, p)
print(f"c1 = g^k mod p = {c1}")

# c2 = hash * A^k mod p - CRIPTAM HASH-UL
print("Criptam hash-ul (nu mesajul intreg)")
c2_hash = (hash_numeric * pow(A, k_random, p)) % p
print(f"c2 = hash * A^k mod p = {c2_hash}")

print(f"\nHash-ul criptat (c1, c2): ({c1}, {c2_hash})")

# DECRIPTARE cu cheia privata
print("\n" + "="*80)
print("DECRIPTARE HASH")
input()

# Pentru a decripta David foloseste privata
# hash = c2 * (c1^a)^(-1) mod p
s = pow(c1, a, p)
print(f"\ns = c1^a mod p = {s}")
s_inv = pow(s, -1, p)
print(f"s^(-1) mod p = {s_inv}")

# Decriptam hash-ul
hash_decrypted_numeric = (c2_hash * s_inv) % p
print(f"\nHash decriptat (numar): {hash_decrypted_numeric}")

# Convertim inapoi in bytes
hash_decrypted = hash_decrypted_numeric.to_bytes(16, byteorder='big')
print(f"Hash decriptat (hex): {hash_decrypted.hex()}")

print("\n" + "="*80)
print("VERIFICARE DECRIPTARE")
input()

# Comparam hash-urile
print("Comparam hash-urile:")
print(f"Hash original:   {hash_md5_msg.hex()}")
print(f"Hash decriptat:  {hash_decrypted.hex()}")

if hash_md5_msg == hash_decrypted:
    print("\n✓ HASH-URI IDENTICE - Decriptarea a reușit!")
    print("Mesajul nu a fost modificat in procesul de criptare/decriptare")
else:
    print("\n✗ Hash-uri diferite - Decriptarea a eșuat!")
    print("Integritatea mesajului este compromisa")

# ============================================================================
# SEMNARE DIGITALA ELGAMAL CU MD5
# ============================================================================

print("\n" + "="*80)
print("SEMNARE DIGITALA ELGAMAL CU MD5")
print("="*80)

input()
# Semnarea mesajului LUNG cu MD5
print("SEMNARE: Calculam semnatura ElGamal cu hash MD5")
print(f"Mesajul: {m[:70]}...")

signature, hash_md5_sign = elgamal_sign(m, p, g, a)
r, s = signature

print(f"\nHash MD5 al mesajului: {hash_md5_sign.hex()}")
print(f"Lungime hash: {len(hash_md5_sign)} octeti (128 biti)")
print(f"\nSemnatura ElGamal:")
print(f"  r = {r}")
print(f"  s = {s}")

input()
