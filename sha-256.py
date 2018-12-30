from struct import pack, unpack
from attr_helper import init_state_256, K_256
from utils_helper import RotR, ShR

BLOCKSIZE = 64


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
    
    a, b, c, d, e, f, g, h = init_state_256

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

    ctx['state'][0] += a
    ctx['state'][1] += b
    ctx['state'][2] += c
    ctx['state'][3] += d
    ctx['state'][4] += e
    ctx['state'][5] += f
    ctx['state'][6] += g
    ctx['state'][7] += h


def sha256_update(s):
    s = s.encode() if isinstance(s, bytes) else str(s)
    length = len(s)

    for i in range(length):
        ctx['data'][i] = ord(s[i])
        ctx['datalen'] += 1

        if ctx['datalen'] == 64:
            sha256_transform()
            ctx['bitlen'] += 512
            ctx['datalen'] = 0
    # ctx['data'][-1] = (len(s)<<3) & 0xffffffff

def sha256_final():

    i = ctx['datalen']

    if ctx['datalen'] < 56:
        ctx['data'][i] = 0x80
        i += 1

        while i < 56:
            ctx['data'][i] = 0x00
            i += 1
    else:
        ctx['data'][i] = 0x80
        i += 1
        while i < 64:
            ctx['data'][i] = 0x00
        sha256_transform()

    ctx['bitlen'] += ctx['datalen'] * 8
    ctx['data'][63] = ctx['bitlen']
    ctx['data'][62] = ctx['bitlen'] >> 8
    ctx['data'][61] = ctx['bitlen'] >> 16
    ctx['data'][60] = ctx['bitlen'] >> 24
    ctx['data'][59] = ctx['bitlen'] >> 32
    ctx['data'][58] = ctx['bitlen'] >> 40
    ctx['data'][57] = ctx['bitlen'] >> 48
    ctx['data'][56] = ctx['bitlen'] >> 56
    sha256_transform()

    h = [0] * 32

    for i in range(4):
        h[i] = (ctx['state'][0] >> (24 - i * 8)) & 0xff
        h[i + 4] = (ctx['state'][1] >> (24 - i * 8)) & 0xff
        h[i + 8] = (ctx['state'][2] >> (24 - i * 8)) & 0xff
        h[i + 12] = (ctx['state'][3] >> (24 - i * 8)) & 0xff
        h[i + 16] = (ctx['state'][4] >> (24 - i * 8)) & 0xff
        h[i + 20] = (ctx['state'][5] >> (24 - i * 8)) & 0xff
        h[i + 24] = (ctx['state'][6] >> (24 - i * 8)) & 0xff
        h[i + 28] = (ctx['state'][7] >> (24 - i * 8)) & 0xff

    print([hex(s)[2:] for s in h])


if __name__ == '__main__':
    sha_init()
    t = 'abc'
    for i, l in enumerate(t):
        ctx['data'][i] = ord(l)
    ctx['data'][len(t)] = 0x80
    ctx['data'][-1] = len(t) << 3 & 0xffffffff

    sha256_transform()
    # sha256_update('password')
    sha256_final()
    print(ctx['data'])