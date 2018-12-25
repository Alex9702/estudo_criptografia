# Inicialição do buffer de 512 bits
# https://bitbucket.org/pypy/pypy/src/tip/lib_pypy/_sha256.py?fileviewer=file-view-default

a = '6A09E667F3BCC908'
b = 'BB67AE8584CAA73B'
c = '3C6EF372FE94F82B'
d = 'A54FF53A5F1D36F1'
e = '510E527FADE682D1'
f = '9B05688C2B3E6C1F'
g = '1F83D9ABFB41BD6B'
h = '5BE0CD19137E2179'

SHA_BLOCKSIZE = 64
SHA_DIGESTSIZE = 32


def new_shaobject():
    return {
        'digest': [0]*8,
        'count_lo': 0,
        'count_hi': 0,
        'data': [0]* SHA_BLOCKSIZE,
        'local': 0,
        'digestsize': 0
    }

ROR = lambda x, y: (((x & 0xffffffff) >> (y & 31)) | (x << (32 - (y & 31)))) & 0xffffffff
Ch = lambda x, y, z: (z ^ (x & (y ^ z)))
Maj = lambda x, y, z: (((x | y) & z) | (x & y))
S = lambda x, n: ROR(x, n)
R = lambda x, n: (x & 0xffffffff) >> n
Sigma0 = lambda x: (S(x, 2) ^ S(x, 13) ^ S(x, 22))
Sigma1 = lambda x: (S(x, 6) ^ S(x, 11) ^ S(x, 25))
Gamma0 = lambda x: (S(x, 7) ^ S(x, 18) ^ R(x, 3))
Gamma1 = lambda x: (S(x, 17) ^ S(x, 19) ^ R(x, 10))

