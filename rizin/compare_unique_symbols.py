capa_symbols = []
with open("rizin/allFounds_capa_sigs.txt", "r") as f:

    capa_symbols = [sym.strip() for sym in f.readlines()]

rizin_symbols = []
with open("rizin/allFounds_rizin_sigs.txt", "r") as f:
    rizin_symbols = [sym.strip() for sym in f.readlines()]

print("capas symbols  - " + str(len(capa_symbols)))
print("rizins symbols - " + str(len(rizin_symbols)))

i = 0
for symbol in rizin_symbols:
    if symbol in capa_symbols:
        i+=1
print("Number of symbols names common to capa and rizin symbols : " + str(i))

