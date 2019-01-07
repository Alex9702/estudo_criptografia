from hash.attr_helper import K_512, init_state_512
from hash.utils_helper import RotR, ShR

blocksize = 128
pad = 0xffffffffffffffff

ctx = {
    'data': None,
    'datalen': 0,
    'bitlen': 0,
    'state': None
}

def sha_init(ctx):
    ctx['data'] = [0] * blocksize
    ctx['datalen'] = 0
    ctx['bitlen'] = 0
    ctx['state'] = list(init_state_512)

Ch = lambda x, y, z: (x & y) ^ (~x & z)
Maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)
sigma0 = lambda x: RotR(x, 28) ^ RotR(x, 34) ^ RotR(x, 39)
sigma1 = lambda x: RotR(x, 14) ^ RotR(x, 18) ^ RotR(x, 41)
gamma0 = lambda x: RotR(x, 1) ^ RotR(x, 8) ^ ShR(x, 7)
gamma1 = lambda x: RotR(x, 19) ^ RotR(x, 61) ^ ShR(x, 6)

def sha_transform(ctx):
    w = [0] * 80
    m = ctx['data']
    for i in range(16):
        j = i * 8
        w[i] = (m[j] << 56 | m[j+1] << 48 | m[j+2] << 40 | 
                m[j+3] << 32 | m[j+4] << 24 | m[j+5] << 16 | 
                m[j+6] << 8 | m[j+7]) & pad

    for i in range(16, 80):
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]

        a,b,c,d,e,f,g,h = ctx['state']

    for i in range(80):
        T1 = h + sigma1(e) + Ch(e,f,g) + K_512[i] + w[i]
        T2 = sigma0(a) + Maj(a,b,c)
        h = g
        g = f
        f = e
        e = d + T1
        d = c
        c = b
        b = a
        a = T1 + T2

    state = (a,b,c,d,e,f,g,h)
    for index, s in enumerate(state):
        ctx['state'][index] = (ctx['state'][index] + s) & pad

def sha_update(ctx, msg):
    ctx['state'] = list(init_state_512)
    ctx['bitlen'] -= ctx['datalen'] * 8
    for letter in msg:
        ctx['data'][ctx['datalen']] = ord(letter)
        ctx['datalen'] += 1
        if ctx['datalen'] == blocksize:
            sha_transform(ctx)
            ctx['data'] = [0] * blocksize
            ctx['bitlen'] += blocksize * 8
            ctx['datalen'] = 0

def sha_final(ctx):
    i = ctx['datalen']
    ctx['data'][i] = 0x80
    i += 1

    if i > blocksize - 16:
        sha_transform(ctx)
        ctx['data'] = [0] * blocksize

    ctx['bitlen'] += ctx['datalen'] * 8
    ctx['data'][112] = (ctx['bitlen'] >> 120) & 0xff
    ctx['data'][113] = (ctx['bitlen'] >> 112) & 0xff
    ctx['data'][114] = (ctx['bitlen'] >> 104) & 0xff
    ctx['data'][115] = (ctx['bitlen'] >> 96) & 0xff
    ctx['data'][116] = (ctx['bitlen'] >> 88) & 0xff
    ctx['data'][117] = (ctx['bitlen'] >> 80) & 0xff
    ctx['data'][118] = (ctx['bitlen'] >> 72) & 0xff
    ctx['data'][119] = (ctx['bitlen'] >> 64) & 0xff
    ctx['data'][120] = (ctx['bitlen'] >> 56) & 0xff
    ctx['data'][121] = (ctx['bitlen'] >> 48) & 0xff
    ctx['data'][122] = (ctx['bitlen'] >> 40) & 0xff
    ctx['data'][123] = (ctx['bitlen'] >> 32) & 0xff
    ctx['data'][124] = (ctx['bitlen'] >> 24) & 0xff
    ctx['data'][125] = (ctx['bitlen'] >> 16) & 0xff
    ctx['data'][126] = (ctx['bitlen'] >> 8) & 0xff
    ctx['data'][127] = ctx['bitlen']
    sha_transform(ctx)

class Sha512:
    def __init__(self, message=''):
        sha_init(ctx)
        self.update(message)

    def digest(self):
        return ctx['state']

    def hexdigest(self):
        return ''.join([(16-len(hex(s)[2:])) * '0' + hex(s)[2:] for s in self.digest()])

    def update(self, message):
        sha_update(ctx, message)
        sha_final(ctx)