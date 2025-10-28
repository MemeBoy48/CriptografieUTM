import random
SHIFT_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
def k_plus_generator():
    k_plus = ""
    for _ in range(56):
        k_plus += str(random.randint(0, 1))
        key = k_plus
    return k_plus

def key_input():
    print("Introdu cheia K+ (56 biti, doar 0 si 1):")
    k_plus = input()
    while len(k_plus) != 56 or all(bit not in '01' for bit in k_plus):
        print("Cheia trebuie sa aiba exact 56 de biti (doar 0 si 1). Introdu din nou:")
        k_plus = input()
    key = k_plus
    return k_plus
def left_shift(bits, i):
    return bits[i:] + bits[:i]


def generare_chei():
    C = key[:28]
    D = key[28:]
    c = []
    d = []
    for shift in SHIFT_TABLE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        c.append(C)
        d.append(D)
    return c, d


def lab4():
    print(f"Cheia K+ generata este: {key}")
    print("-" * 80)
    C_0 = key[:28]
    D_0 = key[28:]
    print (f"Cheia C0 este: {C_0}")
    print("-" * 64)
    print (f"Cheia D0 este: {D_0}")
    print("-" * 64)
    print("Introdu numarul i (0..16):")
    i = input()
    while i.isdigit() == False:
        print("Nu pune nic o litera sau negativ, introduceti un numar intreg intre 0 si 16.")
        i = input()
    i = int(i)
    C, D = generare_chei()
    if 0 <= i <= 16:
        for k in range(0, i+1):
            if k == 0:
                print(f"Cheia C0 este: {C_0}")
                print(f"Cheia D0 este: {D_0}")
            else:
                print(f"Cheia C{k} este: {C[k-1]}")
                print(f"Cheia D{k} este: {D[k-1]}")
            
            print("-" * 45)



print("Meniu:")
print("1. Genereaza cheia K+ si afiseaza cheile Ci si Di pana la i")
print("2. Introduce cheia K+ manual")
print("0. Iesire")
if True:
    choice = input("Alege o optiune (1, 2, 0): ")
    while choice not in ['0', '1', '2']:
        print("Optiune invalida. Te rog alege 1, 2 sau 0.")
        choice = input("Alege o optiune (1, 2, 0): ")
    
    if choice == '1':
        key = k_plus_generator()
        lab4()
    elif choice == '2':
        key = key_input()
        lab4()
    elif choice == '0':
        exit()