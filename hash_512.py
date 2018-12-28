# from struct import pack, unpack
# from attr_helper import init_buffer, sha_constants
# from utils_helper import RotR, ShR

# BLOCKSIZE = 128
# DIGESTSIZE = 64
# output_size = 8
# # Inicia buffer
# h_buffer = [e for e in init_buffer]

# sigma0 = lambda x: RotR(x, 28) ^ RotR(x, 34) ^ RotR(x, 39)
# sigma1 = lambda x: RotR(x, 14) ^ RotR(x, 18) ^ RotR(x, 41)
# gamma0 = lambda x: RotR(x, 1) ^ RotR(x, 8) ^ ShR(x, 7)
# gamma1 = lambda x: RotR(x, 19) ^ RotR(x, 61) ^ ShR(x, 6)
# Maj = lambda x, y, z: (x & y) ^ (~x ^ y)
# Ch = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)

data = [0] * 80
data[0] = 0x80
for i in range(1,16):
    data[i] = int(hex(ord('a'))[2:], 10)
w = []

for i in range(16):
    w.append((data[4*i]<<24) ^ (data[4*i+1]<<16) ^ (data[4*i+2]<<8) ^ data[4*i+3])

print(w)