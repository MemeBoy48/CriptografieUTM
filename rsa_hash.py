from Crypto.Util import number
import math
import random
import sys

# Ssunt prea mari numerele, sad:(
sys.set_int_max_str_digits(10000)


def md2_hash(data):
    """
    MD2 este o functie hash criptografica care genereaza o iesire de 128 biti 
    pentru orice mesaj de intrare. 
    
    Structura algoritmului MD2:
    1. PADDING - Completeaza mesajul la multiplu de 16 octeti
    2. CHECKSUM - Calculeaza o suma de control pe 16 octeti
    3. INITIALIZARE - Pregateste starea interna (3 blocuri X 16 octeti)
    4. PROCESARE - Aplica transformari pe fiecare bloc de 16 octeti
    5. REZULTAT - Extrage primii 16 octeti ca hash final
    
    ============================================================================
    """
    
    # Asiguram ca datele sunt bytes (octeti)
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # ========================================================================
    # TABEL S-BOX (Substitution Box)
    # ========================================================================
    # Aceasta este o permutare a valorilor 0-255, folosita pentru:
    # - Substituire neliniara (non-linear transformation)
    # - Dispersie (avalanche effect) - o mmica schimbare in intrare -> mare
    #   schimbare in iesire
    # - Securitate criptografica
    S = [
        0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13, 
        0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA, 
        0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12, 
        0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A, 
        0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
        0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03, 
        0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6, 
        0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1, 
        0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02, 
        0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F, 
        0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26, 
        0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52, 
        0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A, 
        0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39, 
        0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A, 
        0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14
    ]
    
    # SCOPUL: Siguram ca lungimea mesajului este multiplu de 16 octeti
    
    msg_len = len(data)
    pad_len = 16 - (msg_len % 16)  # Calculam octeti de padding necesari
    padded_data = data + bytes([pad_len] * pad_len)  # Adaugam padding
    
    print(f"PASUL 1 - PADDING")
    print(f"  Lungimea originala: {msg_len} octeti")
    print(f"  Octeti de padding adaugati: {pad_len}")
    print(f"  Lungimea dupa padding: {len(padded_data)} octeti\n")
    
    # ========================================================================
    # PASUL 2: CHECKSUM (Suma de Control)
    # ========================================================================
    # SCOPUL: Detecta erorile si creaza dependenta intre blocuri
    # MODUL: Calculam un checksum pe 16 octeti procesand mesajul padding
    #
    # ALGORITM:
    # - Initializam checksum cu 16 octeti = 0
    # - Pentru fiecare octet din mesaj:
    #   1. C = checksum[i mod 16]
    #   2. T = mesaj[i] XOR L  (L = ultima valoare din checksum)
    #   3. C = C XOR S[T]
    #   4. L = C
    
    checksum = bytearray(16)  # Checksum initial = 0
    L = 0  # Ultima valoare din checksum
    
    for i in range(len(padded_data)):
        c = padded_data[i]
        # Calculam indexul pentru S-box: c XOR L
        sbox_idx = (c ^ L) & 0xFF
        # XOR checksum[i mod 16] cu S[sbox_idx]
        checksum[i % 16] = (checksum[i % 16] ^ S[sbox_idx]) & 0xFF
        # Actualizam L cu noua valoare a checksum-ului
        L = checksum[i % 16]
    
    # Adaugam checksum-ul la mesaj (16 octeti suplimentari)
    padded_data = padded_data + bytes(checksum)
    
    print(f"PASUL 2 - CHECKSUM")
    print(f"  Checksum calculat: {checksum.hex()}")
    print(f"  Lungimea dupa checksum: {len(padded_data)} octeti\n")
    
    # ========================================================================
    # PASUL 3: INITIALIZARE (Starea interna)
    # ========================================================================
    # SCOPUL: Pregatim 3 blocuri de 16 octeti = 48 octeti total
    # STRUCTURA:
    # - X[0:16]   = Stare A (initial 0)
    # - X[16:32]  = Stare B (va contine blocul curent)
    # - X[32:48]  = Stare C (va contine A XOR B)
    
    X = bytearray(48)  # Starea interna = 3 blocuri de 16 octeti
    
    print(f"PASUL 3 - INITIALIZARE")
    print(f"  Starea interna X = 48 octeti (0x00 la inceput)\n")
    
    # ========================================================================
    # PASUL 4: PROCESARE (Transformari principale)
    # ========================================================================
    # SCOPUL: Aplicam transformari neliniare pe fiecare bloc
    # MODUL: 
    # - Pentru fiecare bloc de 16 octeti:
    #   1. Copiem blocul in starea B
    #   2. Calculam C = B XOR A
    #   3. Aplicam 18 runde de transformari
    
    print(f"PASUL 4 - PROCESARE BLOCURI")
    print(f"  Total blocuri de procesat: {len(padded_data) // 16}\n")
    
    block_num = 0
    for block_idx in range(0, len(padded_data), 16):
        block_num += 1
        block = padded_data[block_idx:block_idx + 16]
        
        print(f"  Bloc #{block_num}: Proceseaza octeti {block_idx}-{block_idx+15}")
        
        # ====================================================================
        # Pasul 4a: Copiem blocul in starea X
        # ====================================================================
        # X[16:32] = Blocul curent
        # X[32:48] = Blocul curent XOR Prima parte a starii (X[0:16])
        for i in range(16):
            X[16 + i] = block[i]  # Blocul in starea B
            X[32 + i] = (X[16 + i] ^ X[i]) & 0xFF  # Starea C = B XOR A
        
        print(f"    - Bloc copiat in X[16:32]")
        print(f"    - Calculat X[32:48] = X[0:16] XOR Bloc")
        
        # ====================================================================
        # Pasul 4b: Runde de transformare (18 runde)
        # ====================================================================
        # SCOPUL: Aplicam transformari neliniare iterativ
        # MODUL: Pentru fiecare runda (0-17):
        #   - Procesam toti cei 48 de octeti
        #   - T = X[j] XOR S[T]
        #   - X[j] = T
        #   - La sfarsit: T = (T + numar_runda) mod 256
        
        T = 0  # Valoarea de transformare incepe de la 0
        
        for round_idx in range(18):
            print(f"      Runda {round_idx + 1:2d}/18:", end="")
            
            # Procesam toti cei 48 de octeti ai starii
            for j in range(48):
                # Substituire neliniara folosind S-box
                # S[T] retine o valoare pseudoaleatoare
                # XOR-ul impreuna creeaza o mixare complexa
                T = (X[j] ^ S[T]) & 0xFF
                X[j] = T
            
            # La sfarsitul fiecarei runde, incrementam T cu numarul rundei
            # Aceasta introduce o dependenta de numar de runda
            T = (T + round_idx) & 0xFF
            print(f" T final = 0x{T:02X}")
        
        print(f"    - Runde aplicate: {18}")
        print(f"    - Noua stare X calculata\n")
    
    # ========================================================================
    # PASUL 5: REZULTAT (Extraiere hash final)
    # ========================================================================
    # SCOPUL: Generam hash-ul de 128 biti din starea finala
    # MODUL: Luam primii 16 octeti din starea X (X[0:16])
    
    hash_result = bytes(X[:16])
    
    print(f"[DEBUG MD2] PASUL 5 - REZULTAT FINAL")
    print(f"  Hash MD2 = X[0:16] = {hash_result.hex()}")
    print(f"  Lungime hash: {len(hash_result)} octeti (128 biti)\n")
    
    return hash_result


# ============================================================================
# FUNCTIILE DE SEMNARE DIGITALA
# ============================================================================

def digital_sign(message, d, n):
    """
    Semneaza un mesaj folosind semnatura RSA cu hash MD2
    semnatura = hash(mesaj)^d mod n
    """
    # Calculam hash-ul MD2 al mesajului
    hash_value = md2_hash(message)
    
    # Convertim hash-ul in numar intreg
    hash_int = int.from_bytes(hash_value, byteorder='big')
    
    # Semnuram folosind RSA: semnatura = hash^d mod n
    # Folosim cheia privata d
    signature = pow(hash_int, d, n)
    
    return signature, hash_value


def verify_signature(message, signature, e, n):
    """
    Verifica o semnatura digitala RSA cu hash MD2
    hash_verificat = semnatura^e mod n
    Returneaza True daca semnatura este valida, False altfel
    """
    # Calculam hash-ul MD2 al mesajului
    hash_value = md2_hash(message)
    
    # Convertim hash-ul in numar intreg
    hash_int = int.from_bytes(hash_value, byteorder='big')
    
    # Verificam semnatura folosind RSA: hash_verificat = semnatura^e mod n
    # Folosim cheia publica e
    hash_verified = pow(signature, e, n)
    
    # Comparam hash-urile - daca sunt egale, semnatura este valida
    return hash_verified == hash_int, hash_value, hash_verified


# Cel mai mare divizor comun
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

#Algoritmul extins al lui Euclid pentru a afla inversul modula
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

#Se calculeaza inversa modulara
def mod_invers(e, phi):
    gcd_val, x, y = extended_gcd(e, phi)
    return x % phi


mesaj = "Vigenère was born in the village of Saint-Pourcain, " \
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
"Paris, married the much younger Marie Vare, and devoted himself to his writing. " \
"His Traicté des Chiffres, which was written in 1585 despite the distraction of a " \
"year-old baby daughter, appeared elegantly rubricated in 1586 and was reprinted " \
"the following year. His autokey system used the plaintext as the key. " \
"It provided a priming key. This consisted of a single letter, known to " \
"both encipherer and decipherer, with which the decipherer could decipher " \
"the first cryptogram letter and so get a start on his work. With this," \
" he would get the first plaintext letter, then use this as the key to decipher " \
"the second cryptogram letter, use that plaintext as the key to decipher the " \
"third cryptogram letter, and so on.The system works well and affords fair " \
"guarantees of security; it has been embodied in a number of modern cipher machines=. " \
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
print("Mesaj original: ", mesaj)
input()

# Generarea p si q
print("Generare prime de 1536 biti pentru n de 3072 biti")
p = number.getPrime(1536)
q = number.getPrime(1536)
print(f"p = {p}")
print(f"q = {q}")
print(f"MMarimea lui p: {p.bit_length()} biti")
print(f"MMarimea lui q: {q.bit_length()} biti\n")
input()

# calculeaza n = p * q
n = p * q
print(f"n = {n}")
print(f"Marimea lui n: {n.bit_length()} biti\n")
input()

# Calculeaza fi(n) = (p-1) * (q-1)
print("Se caluclaeza fi(n) = (p-1) * (q-1)")
phi_n = (p - 1) * (q - 1)
print(f"fi(n) = {phi_n}\n")
input()

# Selectare exponent public e astfel ca gcd(e, fi(n)) = 1
print("Se selecteaza exponentul public E astfel ca gcd(e, fi(n)) = 1")
# selectare e random prin random choice dintr-o lista sa fie mai rapid
while True:
    e = random.choice([2, 3, 5, 17, 257, 65537])
    if gcd(e, phi_n) == 1:
        break
print(f"e = {e}\n")
# Calculare cheie privata d astfel ca d * e ≡ 1 mod fi(n)
print("Calculare cheie privata d astfel ca d * e ≡ 1 mod fi(n)")
d = mod_invers(e, phi_n)
print(f"d = {d}")
print(f"\nVerificare: (d * e) mod fi(n) = {(d * e) % phi_n}\n")

input()
# Afisam cheia
print(f"\nCheie publica k_pub = (n, e):")
print(f"  n = {n}")
print(f"  e = {e}")
print(f"\nCheie privata k_pr = d:")
print(f"  d = {d}\n")

input()
# Crriptam mesajul cu formula: y = x^e mod n
# NOTA: Pentru mesaje lungi, se cripteaza hash-ul, nu mesajul intreg
print("CRIPTARE: Calculam hash MD2 si criptam hash-ul")
print("(Pentru mesaje lungi, se cripteaza hash MD2, nu mesajul intreg)")

# Calculam hash MD2 al mesajului
hash_msg = md2_hash(mesaj)
print(f"\nHash MD2 al mesajului: {hash_msg.hex()}")
print(f"Lungime hash: {len(hash_msg)} octeti (128 biti)")

# Convertim hash-ul in numar intreg
x = int.from_bytes(hash_msg, byteorder='big')
print(f"\nHash ca numar: x = {x}")

input()
# Criptarea hash-ului
print("\nCRIPTARE HASH: y = hash^e mod n")
y = pow(x, e, n)  # y = x^e mod n
print(f"Hash criptat: y = {y}\n")

input()
# Decriparea
print("DECRIPTARE HASH: x = y^d mod n")
x_decriptat = pow(y, d, n)  # x = y^d mod n
print(f"Hash decriptat: x = {x_decriptat}\n")

input()
# Comparare
print("Verificare decriptare:")
print(f"Hash original:   {x}")
print(f"Hash decriptat:  {x_decriptat}")
if x == x_decriptat:
    print("✓ Hash-ul decriptat ESTE IDENTIC cu hash-ul original!")
else:
    print("✗ Eroare: Hash-urile NU sunt identice!")

# ============================================================================
# SEMNARE SI VALIDARE DIGITALA (RSA cu MD2)
# ============================================================================

input()
print("\n" + "="*80)
print("SEMNARE SI VALIDARE DIGITALA A MESAJULUI (RSA cu MD2)")
print("="*80 + "\n")

input()
# Semnarea mesajului
print("SEMNARE: Semnatura = hash(mesaj)^d mod n")
signature, hash_original = digital_sign(mesaj, d, n)
print(f"Hash MD2 al mesajului: {hash_original.hex()}")
print(f"Semnatura: {signature}\n")
input()
# Validarea semnaturii
print("VALIDARE: hash_verificat = semnatura^e mod n")
is_valid, hash_msg, hash_ver = verify_signature(mesaj, signature, e, n)
print(f"Hash-ul original (calculat): {hash_msg.hex()}")
print(f"Hash-ul verificat: {hash_ver.to_bytes(16, byteorder='big').hex()}")
print(f"Sunt egale? {is_valid}")

if is_valid:
    print("\n SEMNATURA ESTE VALIDA - Mesajul nu a fost modificat")
    print(f"  Mesaj: {mesaj}")
else:
    print("\n SEMNATURA ESTE INVALIDA - Mesajul a fost modificat sau semnatura este falsa")
