# mdc de dois números
def mdc(x, y):
    while y > 0:
        n = x % y
        x = y
        y = n
    return x

# retorna o t(n) -> Totiene de Euler
def totiene(n):
    return len([i for i in range(1, n) if mdc(n, i) == 1])

# O totiene de dois números primos retorna sempre (p1 - 1) * (p2 - 2)
# x, y = 17 ,13
# print(totiene(x*y))
# print((x - 1) * (y - 1))
# 192
# 192


# Retorna uma lista de números primos até n
def lista_primos(n):
    return [i for i in range(1, n) if totiene(i) == i - 1]

print(lista_primos(1000))
    
