# Algoritmo para criptografia de textos em RSA

frase =  'Esta frase tem que ser secreta!'

# chaves privadas
p, q = 1151, 1217
n = p * q
totienen = (p - 1) * (q - 1)

# d é o inverso multiplicativo de e:t(n) ou seja d * e == 1 mod(t(n))
e, d = 0, 0

# 1 < e < t(n) e não podem possuir divisores comuns.
for i in range(2, totienen - 1):
    if e == 0:
        if totienen % i != 0:
            e = i
    d = i
    if d != 0 and (d * e)%totienen == 1:
        break

# C = M^e mod(n) Codificação da frase.
# C: é a codificação em si.
# M é cada letra da frase.
# e: e
# mod(n) é o módulo de n.
lista_inteiros_codificados = [(ord(m)**e)%n for m in frase]
print(lista_inteiros_codificados)

# M = C^d mod(n)
lista_inteiros_decodificados = ''.join([chr(c**d % n) for c in lista_inteiros_codificados])
print(lista_inteiros_decodificados)


# print(f'frase codificada:\n{frase_codificada}')
# print(f'frase decodificada:\n{frase_decodificada}')
print(f'n: {n}\nTotiene de n: {totienen}\ne: {e}\nd: {d}\nChaves públicas:({n};{e})\nChaves Privadas: ({p};{q};{d})')
