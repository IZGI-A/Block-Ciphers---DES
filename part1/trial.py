def handleKey(key: str):

    key = key.encode('utf-8')
    key = key.ljust(8, b'\0')[:8]
    print(type(key))
    return key

public_key = "example"
initial_value = "sampleinitialvaluestring"

public_key_byte_array = handleKey(public_key)
initial_value_byte_array = handleKey(initial_value)

print("Public Key Byte Array:", public_key_byte_array)
print("Initial Value Byte Array:", initial_value_byte_array)
print(len(public_key_byte_array))
print(len(initial_value_byte_array))

def stringToBits(data):
    """
    Transforms a list of bytes into a list of bits.
    """
    N = len(data) * 8
    result = [0] * N
    pos = 0
    for ch in data:
        i = 7
        while i >= 0:
            if ch & (1 << i) != 0:
                result[pos] = 1
            else:
                result[pos] = 0
            pos += 1
            i -= 1
    return result
block = stringToBits(public_key_byte_array)
print(block)
print(len(stringToBits(public_key_byte_array)))

def bitsToString(data):
    """
    Transforms a list of bits into a list of bytes.
    """
    result = list()
    pos, c = 0, 0
    while pos < len(data):
        c += data[pos] << (7 - (pos % 8))
        if (pos % 8) == 7:
            result.append(c)
            c = 0
        pos += 1
    return bytes(result)

dec =
byte_array = bytearray(dec)

# Convert bytearray to string
result_string = byte_array.decode('utf-8')

print("Byte Array:", byte_array)
print("Resulting String:", result_string)
print(dec)

PC1 = [56, 48, 40, 32, 24, 16, 8,
       0, 57, 49, 41, 33, 25, 17,
       9, 1, 58, 50, 42, 34, 26,
       18, 10, 2, 59, 51, 43, 35,
       62, 54, 46, 38, 30, 22, 14,
       6, 61, 53, 45, 37, 29, 21,
       13, 5, 60, 52, 44, 36, 28,
       20, 12, 4, 27, 19, 11, 3
       ]

def permutation(block, table):
    return list(map(lambda x: block[x], table))

sub = permutation(block, PC1)
print(sub)
print(len(sub))
list = [[1,2,3],[4,6,7],[8,9,0]]

b =  list[::-1]
print(b)

for cbc
if crypt_type == self.ENCRYPTION:
    cipherBlock = xor(cipherBlock, previous_block) if previous_block else cipherBlock
else:
    previous_block = cipherBlock.copy()
    cipherBlock = self._chunk_crypt(cipherBlock, crypt_type)