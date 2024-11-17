from aesFunctions import *

# AES Decryption
def aes_decrypt(ciphertext, key):
    state = np.array(ciphertext).reshape(4,4)
    round_keys = key_expansion(key)

    print("Initial Key:")
    print(round_keys[10])

    add_round_key(state, round_keys[10])
    print("Initial State after AddRoundKey:")
    print("State: ", end="")
    print(*state, sep=", ")

    for round in range(9, 0, -1):
        shift_rows(state, inverse=True)
        sub_bytes(state, inverse=True)
        add_round_key(state, round_keys[round])
        mix_columns(state, inverse=True)
        print(f"Round {round}:")
        print("Key:", round_keys[round])
        print("State: ", end="")
        print(*state, sep=", ")

    shift_rows(state, inverse=True)
    sub_bytes(state, inverse=True)
    add_round_key(state, round_keys[0])
    print("Final Round:")
    print("Key:", round_keys[0])
    print("State: ", end="")
    print(*state, sep=", ")
    
    final_state = []
    for i in range(4):
        for j in range(4):
            final_state.append(state[i][j])
    
    return final_state
