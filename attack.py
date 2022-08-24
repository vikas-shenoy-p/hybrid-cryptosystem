from Cryptodome.Cipher import AES


def check_for_attack(ciphertext, modulus, exponent):

    if ciphertext < modulus:
        if exponent == 3:
            print("\nCube root attack possible")
        else:
            print("Error")


# Implement cube root attack by computing cube root of the RSA ciphertext, which is key for AES
def get_cube_root(number):

    print("Finding cube root of RSA ciphertext to get the key")
    num1, num2 = None, 2

    while num1 != num2:
        num1 = num2
        num3 = num1 ** 3
        d = (2 * num3 + number)
        num2 = (num1 * (num3 + 2 * number) + d // 2) // d

    # Check if the number is a perfect cube or not
    if num1 * num1 * num1 != number:
        return -1
    else:
        # If it is a perfect cube, convert to hex and remove 0x from the beginning
        answer = hex(num1)[2:]
        return answer


def check_aes_length(text):

    # Hex length = 32 bytes * 4 = 128 bits expected for AES cipher, key and plaintext
    expected_block_size = 32
    block_size = len(text)

    if expected_block_size == block_size:
        return print("Length is 128 bits, which is correct")
    else:
        return print("Wrong length")


def check_plaintext_length(text):

    # Byte length should be 16 bytes * 8 = 128 bits expected plaintext
    expected_block_size = 16
    block_size = len(text)

    if expected_block_size == block_size:
        return print("Length is 128 bits, which is correct")
    else:
        return print("Wrong length")


def aes_decrypt(key, ciphertext):

    # The key and ciphertext are already in byte format
    decipher = AES.new(key, AES.MODE_ECB)
    decrypt = decipher.decrypt(ciphertext)
    return decrypt


if __name__ == '__main__':

    print("\n----- Decrypt RSA to get the symmetric key -----")

    # Length of ciphertext and hence message = 98 characters = 392 bits but plaintext/key has to be 128 bits so 128 < 520 so cube root attack
    rsa_ciphertext = 0xc0eacf32dc0492464d9616fefc3d01f56589a137781bf6cf56784dea1c44ef52d61b1025655f370eb78646716f93e0a5

    # Length of modules = 130 characters = 520 bits
    modulus = 0x9c5f36caf9adc60b4447897c639f1564ed0709251147276de030db395555c8afed912a198b334bd230198173128298126e958e38cac653e061035e300505eed1
    exponent = 0x3

    # Test the RSA data given
    check_for_attack(rsa_ciphertext, modulus, exponent)

    temp_key = get_cube_root(rsa_ciphertext)
    print("Key from RSA decryption is: ", temp_key)
    check_aes_length(temp_key)
    key = bytes.fromhex(temp_key)

    print("\n---- Using symmetric key obtained from RSA, decrypt AES ----\n")

    # AES ciphertext is in bytes and so we remove 0x from start of ciphertext and convert to bytes as folows
    ciphertext_aes = 0xfd0b934c23288975648cd1d03ed3c5e2

    # Convert ciphertext to byte array in the following steps
    temp_cipher = hex(ciphertext_aes)
    # AES should always take in and return 128 bit block sizes
    check_aes_length(temp_cipher[2:])

    cipher = bytes.fromhex(temp_cipher[2:])
    print("Ciphertext in bytes:", cipher)
    print("\n-- Decrypting --")
    plaintext = aes_decrypt(key, cipher)
    print("\nDecrypted plaintext is:", plaintext.decode("utf-8"))
    check_plaintext_length(plaintext)

