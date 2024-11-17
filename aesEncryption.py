from aesFunctions import *

# AES Encryption
def aes_encrypt(plaintext, key):
    state = np.array([item for item in plaintext]).reshape(4,4)
    round_keys = key_expansion(key)
    print("Initial Key:")
    print(round_keys[0])

    add_round_key(state, round_keys[0])
    print("Initial State after AddRoundKey:")
    print("State: ", end="")
    print(*state, sep=", ")

    for round in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round])
        print(f"Round {round}:")
        print("Key:", round_keys[round])
        print("State ", end="")
        print(*state, sep=", ")

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    print("Final Round:")
    print("Key:", round_keys[10])
    print("State: ", end="")
    print(*state, sep=", ")

    final_state = []
    for i in range(4):
        for j in range(4):
            final_state.append(state[i][j])

    return final_state