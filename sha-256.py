# from struct import pack, unpack
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
    
    ss = (a,b,c,d,e,f,g,h)
    for i in range(len(ctx['state'])):
        ctx['state'][i] = (ctx['state'][i] + ss[i]) & 0xffffffff


def sha256_update(s):
    pass


def sha256_final():
    pass

if __name__ == '__main__':
    sha_init()
    # t = 'password'
    # for i, l in enumerate(t):
    #     ctx['data'][i] = ord(l)
    # ctx['data'][len(t)] = 0x80
    # ctx['data'][-1] = len(t) << 3 & 0xffffffff

    sha256_transform()
    sha256_update('password')
    sha256_final()
    # print(ctx['state'])