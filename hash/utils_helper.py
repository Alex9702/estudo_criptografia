# helper para os módulos de hash;


def ret_bytes(b):
   if b == 32:
      return 0xffffffff
   elif b == 64:
      return 0xffffffffffffffff


def RotR(x, n, b=64):
    '''Deslocamento circulatório de n bits à direita.
       Atributos:
         : x: int: bits representado por um inteiro.
         : n: int: quantidade de vezes o x binário é rotacionado.
    '''
    return (((x & ret_bytes(b)) >> (n & b - 1)) | (x << (b - (n & b - 1)))) & ret_bytes(b)

def ShR(x, n, b=64):
   '''Desloca n bits à direita.
   Atributos:
      : x: int: números para deslocamento de bits.
      : n: int: quantidade de vezes que os bits são deslocados.
   '''
   return (x & ret_bytes(b)) >> n

if __name__ == '__main__':
   print(RotR(10,2))