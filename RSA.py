from Crypto.Util import number
import math
import random




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


mesaj = "Avram Alexandru"
print("Mesaj original: ", mesaj)
input()

# Generarea p si q
print("Generare prime de 2048 biti pentru n de 4096 biti")
p = number.getPrime(2048)
q = number.getPrime(2048)
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
print("CRIPTARE: y = x^e mod n")
# Convertim mesajul in numar intreg din bytes
mesaj_bytes = mesaj.encode('utf-8')
x = int.from_bytes(mesaj_bytes, byteorder='big')
print(f"Mesajul ca numar: x = {x}\n")

input()
# Criptarea 
y = pow(x, e, n)  # y = x^e mod n
print(f"Mesaj criptat: y = {y}\n")

input()
# Decriparea
print("DECRIPTARE: x = y^d mod n")
x_decriptat = pow(y, d, n)  # x = y^d mod n
print(f"Numar decriptat: x = {x_decriptat}\n")

input()
# Convertim in text
lungime_bytes = (x_decriptat.bit_length() + 7) // 8 # 7 imparte la 8 pentru a rotunji in sus
mesaj_decriptat_bytes = x_decriptat.to_bytes(lungime_bytes, byteorder='big')
mesaj_decriptat = mesaj_decriptat_bytes.decode('utf-8')
print(f"Mesaj decriptat: {mesaj_decriptat}\n")

input()
# Sper ca e correct
print("Verificam sa vedem cat e de corect")
if mesaj == mesaj_decriptat:
    print("YAY, mesajul decriptat este la fel cu mesajul original")
    print(f"  Original:  {mesaj}")
    print(f"  Decriptat: {mesaj_decriptat}")
else:
    print("Ceva am facut gresit mesajele nu aceleasi")
    print(f"  Original:  {mesaj}")
    print(f"  Decriptat: {mesaj_decriptat}")
