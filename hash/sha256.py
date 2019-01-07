# https://github.com/B-Con/crypto-algorithms/blob/master/sha256.c
# FIPS 180-4
# https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=910977
# from struct import pack, unpack
__all__ = ['sha256']
from .attr_helper import init_state_256, K_256
from .utils_helper import RotR, ShR

blocksize = 64

ctx = {'data': [],
    'datalen': 0,
    'bitlen':0,
    'state': []
   }
def sha_init(ctx):
    ctx['data'] = [0] * blocksize
    ctx['datalen'] = 0
    ctx['bitlen'] = 0
    ctx['state'] = list(init_state_256)

# if x then y else z
Ch = lambda x, y, z: (x & y) ^ (~x & z)
# Escolhe o que estiver com os bits batendo com a maioria.
Maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)
sigma0 = lambda x: RotR(x, 2, 32) ^ RotR(x, 13, 32) ^ RotR(x, 22, 32)
sigma1 = lambda x: RotR(x, 6, 32) ^ RotR(x, 11, 32) ^ RotR(x, 25, 32)
gamma0 = lambda x: RotR(x, 7, 32) ^ RotR(x, 18, 32) ^ ShR(x, 3, 32)
gamma1 = lambda x: RotR(x, 17, 32) ^ RotR(x, 19, 32) ^ ShR(x, 10, 32)

def sha_transform(ctx):
    # Processando mensagem.
    # Cada bloco de mensagem conterar 32 bits
    w = [0] * 64
    m = ctx['data']
    
    for i in range(16):
        w[i] = (m[i*4] << 24 | m[i*4+1] << 16 | m[i*4+2] << 8 | m[i*4+3]) & 0xffffffff

    for i in range(16, 64):
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16] & 0xffffffff

    # inicia as variáveis a - h
    a, b, c, d, e, f, g, h = ctx['state']
    
    for i in range(64):
        T1 = h + sigma1(e) + Ch(e, f, g) + K_256[i] + w[i]
        T2 = sigma0(a) + Maj(a, b, c)
        h = g
        g = f
        f = e
        e = d + T1
        d = c
        c = b
        b = a
        a = T1 + T2
    
    state = (a, b, c, d, e, f, g, h)
    for index, s in enumerate(state):
        ctx['state'][index] = (ctx['state'][index] + s) & 0xffffffff

# a messagem tem que ter no máximo 256 bits divididos em 32 words
# caso a mensagem seja maior que 256 bits, é atualizado a mensagem com o restante dos bits
# processado a mensagem anterior.
def sha_update(ctx, msg):
    for letter in msg:
        ctx['data'][ctx['datalen']] = ord(letter)
        ctx['datalen'] += 1
        if ctx['datalen'] == 64:
            sha_transform(ctx)
            ctx['bitlen'] += ctx['datalen'] * 8
            ctx['datalen'] = 0
            ctx['data'] = [0] * blocksize

def sha_final(ctx):
    i = ctx['datalen']
    ctx['data'][i] = 0x80
    i += 1
    if i > 56:
        sha_transform(ctx)
        ctx['data'] = [0] * blocksize

    ctx['bitlen'] += ctx['datalen'] * 8
    ctx['data'][56] = (ctx['bitlen'] >> 56) & 0xff
    ctx['data'][57] = (ctx['bitlen'] >> 48) & 0xff
    ctx['data'][58] = (ctx['bitlen'] >> 40) & 0xff
    ctx['data'][59] = (ctx['bitlen'] >> 32) & 0xff
    ctx['data'][60] = (ctx['bitlen'] >> 24) & 0xff
    ctx['data'][61] = (ctx['bitlen'] >> 16) & 0xff
    ctx['data'][62] = (ctx['bitlen'] >> 8) & 0xff
    ctx['data'][63] = ctx['bitlen'] & 0xff
    sha_transform(ctx)

class Sha256:
    def __init__(self, message=None):
        sha_init(ctx)
        if message:
            self.update(message)
        
    def digest(self):
        sha_final(ctx)
        return ctx['state']
    
    def hexdigest(self):
        sha_final(ctx)
        return ''.join([(8 - len(hex(s)[2:]))*'0' + hex(s)[2:] for s in ctx['state']])
    
    def update(self, message):
        sha_update(ctx, message)