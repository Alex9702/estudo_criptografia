import struct
from utils_helper import buffer256 as buffer
from   utils_helper import words256 as words


SHA_BLOCKSIZE = 64
SHA_DIGESTSIZE = 32

sha_object = {
        'digest': [0]*8,
        'count_lo': 0,
        'count_hi': 0,
        'data': [0]* SHA_BLOCKSIZE,
        'local': 0,
        'digestsize': 0
    }
# Inicialização do buffer
a = buffer['a']
b = buffer['b']
c = buffer['c']
d = buffer['d']
e = buffer['e']
f = buffer['f']
g = buffer['g']
h = buffer['h']

# Função condicional onde retorna verdadeiro se a maioria for verdadeiro.
Maj = lambda x, y, z: ((x | y) & z) | (x & y)
# a função condicional: if x then y else z
Ch = lambda x, y, z: (x & y) ^ (~x & z)
# Shift à direito em n bits.
shr32 = lambda x ,n: (x & 0xffffffff) >> n
# roda os bits para a direita em n bits
ror32 = lambda x, n: (((x & 0xffffffff) >> (n & 31)) | (x << (32 - (n & 31)))) & 0xffffffff

# Funções para embaralhar as palavras de entrada.
Sigma0 = lambda x: (ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22))
Sigma1 = lambda x: (ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25))
Gamma0 = lambda x: (ror32(x, 7) ^ ror32(x, 18) ^ shr32(x, 3))
Gamma1 = lambda x: (ror32(x, 17) ^ ror32(x, 19) ^ shr32(x, 10))

def sha_transform(sha_object):
    W = []
    
    d = sha_object['data']
    for i in range(0,16):
        W.append( (d[4*i]<<24) + (d[4*i+1]<<16) + (d[4*i+2]<<8) + d[4*i+3])
    
    for i in range(16,64):
        W.append( (Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16]) & 0xffffffff )
    
    ss = sha_object['digest'][:]
    
    def RND(a,b,c,d,e,f,g,h,i,ki):
        t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i]
        t1 = Sigma0(a) + Maj(a, b, c)
        d += t0
        h  = t0 + t1
        return d & 0xffffffff, h & 0xffffffff
    for i in range(64):
        ss[(3 - i) % 8], ss[(7 - i) % 8] = RND(ss[(64 - i) % 8], ss[(63 - i) % 8], ss[(62 - i) % 8], ss[(61 - i) % 8], ss[(60 - i) % 8], ss[(59 - i) % 8], ss[(58 - i) % 8], ss[(57 - i) % 8], i, words[i])
    
    dig = []
    for i, x in enumerate(sha_object['digest']):
        dig.append((x + ss[i]) & 0xffffffff)
    sha_object['digest'] = dig

def sha_init():
    sha_object['digest'] =  [b for b in buffer.values()]
    sha_object['count_lo'] = 0
    sha_object['count_hi'] = 0
    sha_object['local'] = 0
    sha_object['digestsize'] = 32
    return sha_object

def sha_final(sha_object):
    lo_bit_count = sha_object['count_lo']
    hi_bit_count = sha_object['count_hi']
    count = (lo_bit_count >> 3) & 0x3f
    sha_object['data'][count] = 0x80
    count += 1
    if count > SHA_BLOCKSIZE - 8:
        # zero the bytes in data after the count
        sha_object['data'] = sha_object['data'][:count] + ([0] * (SHA_BLOCKSIZE - count))
        sha_transform(sha_object)
        # zero bytes in data
        sha_object['data'] = [0] * SHA_BLOCKSIZE
    else:
        sha_object['data'] = sha_object['data'][:count] + ([0] * (SHA_BLOCKSIZE - count))
    
    sha_object['data'][56] = (hi_bit_count >> 24) & 0xff
    sha_object['data'][57] = (hi_bit_count >> 16) & 0xff
    sha_object['data'][58] = (hi_bit_count >>  8) & 0xff
    sha_object['data'][59] = (hi_bit_count >>  0) & 0xff
    sha_object['data'][60] = (lo_bit_count >> 24) & 0xff
    sha_object['data'][61] = (lo_bit_count >> 16) & 0xff
    sha_object['data'][62] = (lo_bit_count >>  8) & 0xff
    sha_object['data'][63] = (lo_bit_count >>  0) & 0xff
    
    sha_transform(sha_object)
    
    dig = []
    for i in sha_object['digest']:
        dig.extend([ ((i>>24) & 0xff), ((i>>16) & 0xff), ((i>>8) & 0xff), (i & 0xff) ])
    return ''.join([chr(i) for i in dig])


def sha_update(sha_object, buffer):
    count = len(buffer)
    buffer_idx = 0
    clo = (sha_object['count_lo'] + (count << 3)) & 0xffffffff
    if clo < sha_object['count_lo']:
        sha_object['count_hi'] += 1
    sha_object['count_lo'] = clo
    
    sha_object['count_hi'] += (count >> 29)
    
    if sha_object['local']:
        i = SHA_BLOCKSIZE - sha_object['local']
        if i > count:
            i = count
        
        # copy buffer
        for x in enumerate(buffer[buffer_idx:buffer_idx+i]):
            sha_object['data'][sha_object['local']+x[0]] = struct.unpack('B', x[1])[0]
        
        count -= i
        buffer_idx += i
        
        sha_object['local'] += i
        if sha_object['local'] == SHA_BLOCKSIZE:
            sha_transform(sha_object)
            sha_object['local'] = 0
        else:
            return
    
    while count >= SHA_BLOCKSIZE:
        # copy buffer
        sha_object['data'] = [struct.unpack('B',c)[0] for c in buffer[buffer_idx:buffer_idx + SHA_BLOCKSIZE]]
        count -= SHA_BLOCKSIZE
        buffer_idx += SHA_BLOCKSIZE
        sha_transform(sha_object)
        
    
    # copy buffer
    pos = sha_object['local']
    sha_object['data'][pos:pos+count] = [struct.unpack('B',c)[0] for c in buffer[buffer_idx:buffer_idx + count]]
    sha_object['local'] = count

def getbuf(s):
    if isinstance(s, str):
        return s
    else:
        return str(s)



class sha256:
    def __init__(self, s=None):
        self._sha = sha_init()
        if s:
            sha_update(self._sha, getbuf(s))

    def digest(self):
        return sha_final(self._sha.copy())[:self._sha['digestsize']]

print(Ch(3,4,1))

