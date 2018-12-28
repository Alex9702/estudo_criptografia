


def RotR(x, n):
    '''Deslocamento circulatório de n bits à direita.
       Atributos:
         : x: int: bits representado por um inteiro.
         : n: int: quantidade de vezes o x binário é rotacionado.
    '''
    return (((x & 0xffffffffffffffff) >> (n & 63)) | (x << (64 - (n & 63)))) & 0xffffffffffffffff

def ShR(x, n):
   '''Desloca n bits à direita.
   Atributos:
      : x: int: números para deslocamento de bits.
      : n: int: quantidade de vezes que os bits são deslocados.
   '''
   return (x & 0xffffffffffffffff) >> n

if __name__ == '__main__':
   print(RotR(10,2))