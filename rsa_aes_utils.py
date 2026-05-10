#If code gives an error you may don't have pycryptodome library.
#First you should write "pip install pycryptodome" to download library in terminal.
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ************ RSA Operations *****************
# This function generates new rsa public anda private key
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key       #Private key
    public_key = key.publickey()        #Public Key
    return private_key, public_key

#This function encrypts data using RSA public key. This is confidentiality
def encrypt_rsa(public_key, data):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_data = cipher_rsa.encrypt(data)
    return enc_data     #Return the encrypted data

#This function decrypts data using RSA private key
def decrypt_rsa(private_key, enc_data):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    data = cipher_rsa.decrypt(enc_data)
    return data     #Return decrypted message.

#This function first hashes the data with SHA256 and signs it using the RSA private key. This is authentication
def sign_data(private_key, data):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

#This is our authentication verification. This is first tries to verify signature, if it is valid returns true, otherwise false.
def verify_signature(public_key, data, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)       #Try to verify signature.
        return True
    except (ValueError, TypeError):
        return False


# ************** AES Operations (Dual Mode: GCM & CTR) ************
#Generates random 16 byte session keys
def generate_session_key(byte_size=16):  # 16 bytes = 128 bit AES
    return get_random_bytes(byte_size)

# Encrypts data with selected mode GCM or CTR.
def encrypt_aes(session_key, plaintext, mode_name):
    data_bytes = plaintext.encode("utf-8")
    #GCM mode encryption.
    if mode_name == "GCM":
        cipher = AES.new(session_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
        return ciphertext, cipher.nonce, tag        #Returns encrypted text, nonce and tag for the gcm mode

    elif mode_name == "CTR":        #CTR mode encryption
        cipher = AES.new(session_key, AES.MODE_CTR)
        ciphertext = cipher.encrypt(data_bytes)
        return ciphertext, cipher.nonce, None       #CTR mode does not produce an authentication tag.
    else:
        raise ValueError("Invalid Mode. Only 'GCM' or 'CTR' are allowed.")


def decrypt_aes(session_key, ciphertext, nonce, mode_name, tag=None):
    # For GCM; Verifies integrity
    if mode_name == "GCM":
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode("utf-8")
        except ValueError:
            return f"\033[91m!!!ERROR!!! Message integrity has been compromised and corrupted!!! MAC VERIFICATION FAILED\033[0m"
    # For CTR, catches decoding errors if data is corrupted
    elif mode_name == "CTR":
        cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
        ctr_plaintext = cipher.decrypt(ciphertext)
        try:        # CTR does not check integrity, so it will try to decrypt even corrupted data.
            return ctr_plaintext.decode("utf-8")
        except UnicodeDecodeError:      # If the result is not valid text (UTF-8), we catch the error here.
            return f"\033[91m!!!ERROR!!! Decryption with CTR was successful but resulted in modified data!!! Raw plaintext: {ctr_plaintext}\033[0m"