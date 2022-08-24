import secrets
import random
import sys
from Crypto.Cipher import AES
from Crypto import Random


def prime_generator(size):
    while True:
        num = random.randrange(2 ** (size - 1), 2 ** (size))
        if isPrime(num):
            return num


def isPrime(n):
    if (n <= 2):
        return False  # All negative values, 0, 1, 2 can't be used in our case.
    low_prime = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
                 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191,
                 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
                 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
                 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499]

    if n in low_prime:
        return True

    for prime in low_prime:
        if (n % prime == 0):
            return False


def gcd_generator(n1, n2):
    # Making use of Euclidian algorithm to calculate the GCD of 2 given numbers
    while n2 != 0:
        temp = n1 % n2
        n1 = n2
        n2 = temp
    return n1


def d_generator(n1, n2):
    # Making use of Extended Euclidian algorithm to find d from given e and phi(n) values
    x = 0
    y = 1
    lx = 1
    ly = 0
    temp1 = n1
    temp2 = n2
    while n2 != 0:
        q = n1 // n2
        (n1, n2) = (n2, n1 % n2)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += temp2
    if ly < 0:
        ly += temp1
    return lx


def RSA_key_generator(size):
    # 1. We generate 2 big random prime numbers(p,q)
    p = prime_generator(size)
    q = prime_generator(size)
    if not (isPrime(p) and isPrime(q)):  # Checking if generated P and Q values are prime or not
        raise ValueError("Both P and Q should be prime numbers")
    elif p == q:  # Test Case 2- checking if p and q values are equal, if equal they can't be used for RSA since if N can be factored(in this case, square root of N would factor N) RSA can be broken.
        raise ValueError("P and Q can't be equal")

    # 2. Next, compute N=q*p and phi(n)=(q-1)*(p-1)
    n = q * p
    phi = (q - 1) * (p - 1)

    # 3. Then, we generate a random integer "e" (public exponent) such that 1<e<phi(n) and gcd(e,phi(n))=1
    e = random.randrange(1, phi)
    g = gcd_generator(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd_generator(e, phi)

    # 4. Next, we generate another integer "d" (private exponent) such that Extended 1<d<phi(n) such that d≡(e^-1)mod phi(n) using Extended Euclidean Algorithm.
    d = d_generator(e, phi)

    # 5. Finally, we return the public and private keys - (e,n) and (d,n) respectively.
    return ((n, e), (d, n))


def RSA_encryption(public_key, plain_text):
    # 1. Acquire n,e
    n, e = public_key
    # 2. Compute c=m^e(mod n)
    c = [(ord(char) ** e) % n for char in plain_text]
    print(c)
    return c


def RSA_decryption(private_key, cipher_text):
    d, n = private_key
    # 1. Compute m=c^d(mod n)
    m = [chr((char ** d) % n) for char in cipher_text]
    return m


def AES_encryption(cipher, plain_text):
    return cipher.encrypt(plain_text.encode("utf-8"))


def AES_decryption(cipher, cipher_text):
    return cipher.decrypt(cipher_text).decode('utf-8')


def main():
    print("RSA-AES Hybrid Encryption System \n")
    print("Sender's End:")
    print("******************************************************************")
    # 1.	The sender generates the RSA public and private keys
    print("Generating RSA public and private keys for AES key encryption and decryption")
    RSA_public_key, RSA_private_key = RSA_key_generator(8)

    # 2.	Then, he/she generates a AES key for the data ecryption
    print("Generating AES key for plain text encryption")
    key = secrets.token_hex(16)
    print(f"AES Key:{key} ")
    AES_key = key.encode("utf-8")

    # 3. Next, the sender encrypts the plain text using the above generated AES key

    plain_text = input("Enter the message to encrypt: ")
    if len(plain_text) == 0 or len(
            plain_text) % 16 != 0:  # Test Case 1 - Checking the length of user's message if it is of size 16 bytes (AES requirement), if not terminating the program.
        raise ValueError("Please enter message that is a mulitple of 16 in length!")
    cipher = AES.new(AES_key, AES.MODE_ECB)
    AES_cipher_text = AES_encryption(cipher, plain_text)
    print("Encrypting the message with AES Algorithm", f"AES Cipher Text:{AES_cipher_text}", sep="\n")

    # 4. Later, the sender encrypts the AES key using RSA
    RSA_cipher_text = RSA_encryption(RSA_public_key, key)
    print("Encrypting the AES key with RSA Algorithm", f"Encrypted AES key:{RSA_cipher_text}", sep="\n")

    # 5.	Lastly, sender sends the RSA and AES cipher texts to receiver
    print("Sending RSA Text (AES key) and AES Cipher Texts to the receiver...")

    print("\n", "Receiver's End:", sep="")
    print("******************************************************************")
    # 1. Receiver uses his/her private key to decrypt the RSA Cipher to obtain the AES key
    AES_decrypted_key = ''.join(RSA_decryption(RSA_private_key, RSA_cipher_text))
    print("Decrypting the AES Cipher text (AES key) with RSA Algorithm", f"Decrypted AES Key:{AES_decrypted_key}",
          sep="\n")
    if len(AES_decrypted_key) == len(
            key):  # Test Case 3- Checking if original AES key and AES key obtained after RSA decryption are the same, if not then the RSA decryption system failed
        if AES_decrypted_key == key:
            print("RSA Decryption Successful!!!", f"Decrypted AES Key:{AES_decrypted_key}", sep="\n")
        else:
            print("RSA Decryption Failed1!!!")
    else:
        print("RSA Decryption Failed!!!")

    # 2. Receiver then uses above obtained AES key to decrypt the AES cipher text
    AES_decrypted_key = AES_decrypted_key.encode("utf-8")
    cipher = AES.new(AES_decrypted_key, AES.MODE_ECB)
    AES_decryption_result = AES_decryption(cipher, AES_cipher_text)
    print("Decrypting the AES Cipher Text using the above AES key")
    if len(AES_decryption_result) == len(
            plain_text):  # Test Case 4- Checking if AES decryption result and original plain text are the same, if not then the AES decryption system failed
        if AES_decryption_result == plain_text:
            print("AES Decryption Successful!!!", f"Decrypted Message:{AES_decryption_result}", sep="\n")
        else:
            print("AES Decryption Failed!!!")
    else:
        print("AES Decryption Failed!!!")


if __name__ == "__main__":
    main()