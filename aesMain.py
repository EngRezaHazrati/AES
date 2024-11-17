from aesEncryption import *
from aesDecryption import *


# Start
des_process = ""
while (des_process == "") or (not (des_process in ["1","2"])):
    print("Please select the process you would like to perform:")
    print("[1] AES algorithm Encryption")
    print("[2] AES algorithm Decryption")
    print("Your Choice [1 | 2]: ", end="")
    des_process = input()

# Student ID = "244328902" -> therefore the main_key = "2443289022443289"
# Input String = "Hello TomorrowHe"
main_key = "2443289022443289"
pl = "Hello TomorrowHe"

match des_process:
    case "1":
        # Encryption process is selected

        plain_text = input("Enter a string as plain text: ")
        main_key = input("Enter your main key: ")

        plaintext = string_to_bytes(plain_text)
        key = string_to_bytes(main_key)

        print("AES Encryption:")
        cipher_text = aes_encrypt(plaintext, key)

        # Flatten the ciphertext state and encode it to Base64
        ciphertext_bytes = bytes([byte for byte in cipher_text ])
        base64_ciphertext = base64.b64encode(ciphertext_bytes).decode('utf-8')

        #print(ciphertext_bytes)
        
        print("\nPlain text: \t", plain_text)
        print("Cipher text: \t", base64_ciphertext)
        print()

    case "2":
        # Decryption process is selected

        base64_ciphertext = input("Enter a string as cipher text: ")
        ciphertext_bytes = base64.b64decode(base64_ciphertext)
        # Convert ciphertext bytes to a state List
        cipher_text = [item for item in ciphertext_bytes]

        main_key = input("Enter your main key: ")
        key = string_to_bytes(main_key)

        print("AES Decryption:")
        decrypted_state = aes_decrypt(cipher_text, key)
        plain_text = bytes_to_string(decrypted_state)

        print("\nCipher text: \t", base64_ciphertext)
        print("Plain text: \t", plain_text)
        print()