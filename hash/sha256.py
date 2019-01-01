# https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
# FIPS 180-4
# https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=910977
# from struct import pack, unpack
__all__ = ['sha256']
from .attr_helper import init_state_256, K_256
from .utils_helper import RotR, ShR

BLOCKSIZE = 64
BITSIZE = 8

ctx = {
    'data': [0] * BLOCKSIZE,
    'datalen': 0,
    'bitlen': 0,
    'state': [0] * 8
}


rotr = lambda x, n: RotR(x, n, 32)
shr = lambda x, n: ShR(x, n, 32)
Ch = lambda x, y, z: (x & y) ^ (~x & z)
Maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)
sigma0 = lambda x: rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
sigma1 = lambda x: rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
gamma0 = lambda x: rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
gamma1 = lambda x: rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)

def sha_init():
    ctx['datalen'] = 0
    ctx['bitlen'] = 0
    for i in range(len(ctx['state'])):
        ctx['state'][i] = init_state_256[i]

def sha256_transform():
    m = [0] * 64
    data = ctx['data']

    for i in range(16):
        m[i] = (data[4*i] << 24 | data[4*i+1] << 16 | data[4*i+2] << 8 | data[4*i+3] ) & 0xffffffff

    for i in range(16, 64):
        m[i] =( gamma1(m[i - 2]) + m[i - 7] + gamma0(m[i - 15]) + m[i - 16]) & 0xffffffff

    a, b, c, d, e, f, g, h = ctx['state']

    for i in range(64):
        T1 = (h + sigma1(e) + Ch(e, f, g) + K_256[i] + m[i]) & 0xffffffff
        T2 = (sigma0(a) + Maj(a, b, c)) & 0xffffffff
        h = g
        g = f
        f = e
        e = (d + T1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xffffffff
    
    ss = (a,b,c,d,e,f,g,h)

    for i in range(len(ctx['state'])):
        ctx['state'][i] = (ctx['state'][i] + ss[i]) & 0xffffffff


def sha256_update(s):
    length = len(s)
    for i in range(length):
        ctx['data'][ctx['datalen']] = ord(s[i])
        ctx['datalen'] += 1
        if ctx['datalen'] == 64:
            sha256_transform()
            ctx['bitlen'] += 512
            ctx['datalen'] = 0
    
def sha256_final():
    h = []
    i = ctx['datalen']
    ctx['data'][i] = 0x80
    i += 1
    if i > BLOCKSIZE - BITSIZE:
        ctx['data'] = ctx['data'][:i] + [0] * (BLOCKSIZE - i)
        sha256_transform()
        ctx['data'] = [0] * BLOCKSIZE
    else:
        ctx['data'] = ctx['data'][:i] + [0] * (BLOCKSIZE - i)
        
    ctx['bitlen'] += ctx['datalen'] * BITSIZE

    ctx['data'][56] = (ctx['bitlen'] >> 56) & 0xff
    ctx['data'][57] = (ctx['bitlen'] >> 48) & 0xff
    ctx['data'][58] = (ctx['bitlen'] >> 40) & 0xff
    ctx['data'][59] = (ctx['bitlen'] >> 32) & 0xff
    ctx['data'][60] = (ctx['bitlen'] >> 24) & 0xff
    ctx['data'][61] = (ctx['bitlen'] >> 16) & 0xff
    ctx['data'][62] = (ctx['bitlen'] >>  8) & 0xff
    ctx['data'][63] = (ctx['bitlen'] >>  0) & 0xff

    sha256_transform()

    h.extend([(8 - len(hex(s)[2:])) * '0' + hex(s)[2:] for s in ctx['state']])
    return ''.join(h)


class sha256:
    def __init__(self, message=None):
        sha_init()
        if message:
            self.update(message)
    
    def update(self, message):
        sha256_update(message)
    
    def hexdigest(self):
        return sha256_final()

if __name__ == '__main__':
    
    t = 'test string'

    print('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == sha256().hexdigest())
    print('d5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b' == sha256(t).hexdigest())
    print('30b5ec0f23e9d95ee0941c55f6f15047bd3978f76f7e554cf4e3b1ea19e30300' == sha256(t*10).hexdigest())

    s = sha256(t)
    s.update(t)
    print('1245a39b7546c1b7f305e43c4bd1cd38e465e317ff4c95f241d5826061253592' == s.hexdigest())


