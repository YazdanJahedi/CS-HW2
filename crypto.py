import constants

def bytes_to_bin(byte_string):
    bin_string = ''.join(f'{byte:08b}' for byte in byte_string)
    return bin_string
def bin_to_bytes(bin_string):
    byte_array = bytearray()
    for i in range(0, len(bin_string), 8):
        byte_array.append(int(bin_string[i:i+8], 2))
    return bytes(byte_array)
def bytes_to_matrix(byte_string):
    matrix = []
    for i in range(0, len(byte_string), 4):
        matrix.append(list(byte_string[i:i+4]))
    return matrix
def matrix_to_bytes(matrix):
    flattened_state = [item for sublist in matrix for item in sublist]
    output = bytes(flattened_state)
    return output
def IP(input_byte_string):
    binary_input = bytes_to_bin(input_byte_string)
    permuted_binary = ''.join([binary_input[constants.IP_TABLE[i]-1] for i in range(len(constants.IP_TABLE))])
    permuted_bytes = bin_to_bytes(permuted_binary)
    return permuted_bytes
def IP_inverse(input_byte_string):
    binary_input = bytes_to_bin(input_byte_string)
    inversed_binary = ''.join([binary_input[constants.IP_INVERSE_TABLE[i]-1] for i in range(len(constants.IP_INVERSE_TABLE))])
    inversed_bytes = bin_to_bytes(inversed_binary)
    return inversed_bytes  
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = constants.S_BOX[state[i][j]]
    return state
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state
def mix_columns(state):
    for i in range(4):
        a = state[i]
        state[i] = [
            gmul(a[0], 2) ^ gmul(a[1], 3) ^ gmul(a[2], 1) ^ gmul(a[3], 1),
            gmul(a[0], 1) ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ gmul(a[3], 1),
            gmul(a[0], 1) ^ gmul(a[1], 1) ^ gmul(a[2], 2) ^ gmul(a[3], 3),
            gmul(a[0], 3) ^ gmul(a[1], 1) ^ gmul(a[2], 1) ^ gmul(a[3], 2),
        ]
    return state
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p & 0xFF
def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state
def F(state, round_key):
    state_matrix = bytes_to_matrix(state)
    round_key_matrix = bytes_to_matrix(round_key)

    state_matrix = sub_bytes(state_matrix)
    state_matrix = shift_rows(state_matrix)
    state_matrix = mix_columns(state_matrix)
    state_matrix = add_round_key(state_matrix, round_key_matrix)

    out_state = matrix_to_bytes(state_matrix)
    return out_state
def sub_word(word):
    return (
        (constants.S_BOX[(word >> 24) & 0xFF] << 24) |
        (constants.S_BOX[(word >> 16) & 0xFF] << 16) |
        (constants.S_BOX[(word >> 8) & 0xFF] << 8) |
        (constants.S_BOX[word & 0xFF])
    )
def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)
def key_expansion(key):
    key_schedule = [0] * 44  # 4 * (10 + 1) words for 128-bit AES
    for i in range(4):
        key_schedule[i] = int.from_bytes(key[4*i:4*(i+1)], byteorder='big')

    for i in range(4, 44):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = sub_word(rot_word(temp)) ^ (constants.RCON[(i // 4) - 1] << 24)
        key_schedule[i] = key_schedule[i - 4] ^ temp

    return key_schedule
import constant 
def get_aes_subkey(key, round_num):
    if round_num < 0 or round_num > 10:
        raise ValueError("Round number must be between 0 and 10")
    expanded_key = key_expansion(key)
    round_key = expanded_key[round_num*4:(round_num+1)*4]
    subkey = b''.join(word.to_bytes(4, byteorder='big') for word in round_key)
    return subkey
def split_byte_string(byte_string):
    if len(byte_string) != 32:
        raise ValueError("Input byte string must be 256 bits (32 bytes) long")

    # Split the byte string into two halves
    left_half = byte_string[:16]
    right_half = byte_string[16:]

    return left_half, right_half

# -------------------------
# -------------------------

def encrypt(plainText, key):
    permuted_text = IP(plainText)

    L , R = split_byte_string(permuted_text)

    for round_num in range(1, constant.ROUNDS_NUMBER + 1):
        subkey = get_aes_subkey(key, round_num)
        F_output = F(R, subkey)

        new_L = R
        new_R = bytes([L[i] ^ F_output[i] for i in range(16)])

        L = new_L
        R = new_R
    
    pre_output = R + L
    cipherText = IP_inverse(pre_output)
    
    return cipherText

def decrypt(cipherText, key):

    permuted_text = IP(cipherText)
    
    L , R = split_byte_string(permuted_text)
    
    for round_num in range(constant.ROUNDS_NUMBER, 0, -1):
        subkey = get_aes_subkey(key, round_num)
        F_output = F(L, subkey)
        
        new_R = L
        new_L = bytes([R[i] ^ F_output[i] for i in range(16)])
        
        L = new_L
        R = new_R
    
    pre_output = R + L
    plainText = IP_inverse(pre_output)
    
    return plainText

