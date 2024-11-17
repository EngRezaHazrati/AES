from aesRequiredTables import *
import numpy as np
import base64

def string_to_bytes(input_string, length=16):
    """Converts a string to a list of hex bytes (padded or truncated to `length`)."""
    input_string = input_string[:length].ljust(length)  # Pad or truncate
    return [ord(char) for char in input_string]

######################################################################

def bytes_to_string(byte_list):
    """Converts a list of hex bytes back to a string."""
    return ''.join(chr(byte) for byte in byte_list)

######################################################################

# Helper function to substitute bytes using the S-box or Inverted S-box
def sub_bytes(state, inverse=False):
    """Perform the SubBytes step using S-box or Inverse S-box."""
    box = inv_s_box if inverse else s_box
    for i in range(4):
        for j in range(4):
            state[i][j] = box[state[i][j] >> 4][state[i][j] & 0x0F]

######################################################################

def shift_rows(state, inverse=False):
    """Perform the ShiftRows step."""
    for i in range(4):
        state[i] = np.roll(state[i], -i if not inverse else i)

######################################################################

# Galois Field multiplication for MixColumns
def galois_multiply(a, b):
    """Perform multiplication in GF(2^8) for AES."""
    result = 0
    for i in range(8):
        if b & 1:  # If the lowest bit of b is 1, add a to result
            result ^= a
        high_bit_set = a & 0x80  # Check if the highest bit is set
        a <<= 1  # Multiply a by 2
        if high_bit_set:  # If the high bit was set, reduce by the AES polynomial
            a ^= 0x1B
        b >>= 1  # Divide b by 2
    return result & 0xFF  # Ensure result is a byte

######################################################################

# MixColumns transformation
def mix_columns(state, inverse=False):
    """Apply the MixColumns step (or its inverse) to the state."""
    if inverse:
        mix_matrix = [
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ]
    else:
        mix_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

    # Multiply each column of the state by the MixColumns matrix
    for col in range(4):  # AES operates on columns
        column = [state[row][col] for row in range(4)]
        new_column = [0] * 4
        for row in range(4):
            new_column[row] = (
                galois_multiply(mix_matrix[row][0], column[0]) ^
                galois_multiply(mix_matrix[row][1], column[1]) ^
                galois_multiply(mix_matrix[row][2], column[2]) ^
                galois_multiply(mix_matrix[row][3], column[3])
            )
        for row in range(4):
            state[row][col] = new_column[row]

######################################################################

# AddRoundKey step
def add_round_key(state, round_key):
    #print("round key: ", round_key)
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[4*i+j]
    return state

######################################################################

def sub_word(word):
    #Apply the S-box to each byte of the word.
    return [s_box[byte >> 4][byte & 0x0F] for byte in word]

def rot_word(word):
    #Rotate a word (4 bytes) left by one byte.
    return word[1:] + word[:1]

######################################################################

def key_expansion(key):
    #Generate the round keys for AES-128 encryption and decryption.

    # Ensure the input key is 16 bytes
    assert len(key) == 16, "Key must be exactly 16 bytes for AES-128."

    # Number of 4-byte words in the key and key schedule
    Nk = 4  # Number of words in the key (AES-128 = 4 words = 16 bytes)
    Nb = 4  # Number of words in a state (block size = 16 bytes = 4 words)
    Nr = 10  # Number of rounds for AES-128

    # Initialize key schedule with the input key
    key_schedule = [key[i:i + 4] for i in range(0, len(key), 4)]

    # Generate the remaining words in the key schedule
    for i in range(Nk, Nb * (Nr + 1)):
        temp = key_schedule[i - 1]

        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp = [temp[j] ^ Rcon[i // Nk - 1][j] for j in range(4)]

        new_word = [key_schedule[i - Nk][j] ^ temp[j] for j in range(4)]
        key_schedule.append(new_word)

    # Convert the key schedule into round keys (16-byte chunks)
    round_keys = []
    for i in range(0, len(key_schedule), Nb):
        round_keys.append([byte for word in key_schedule[i:i + Nb] for byte in word])

    return round_keys

######################################################################

