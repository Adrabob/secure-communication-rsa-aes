#If code gives an error you may don't have pycryptodome library.
#First you should write "pip install pycryptodome" to download library in terminal.
import rsa_aes_utils
import time

class User:
    def __init__(self, name):
        self.name = name
        print(f"[{self.name}] Generating RSA key pair...")
        self.private_key, self.public_key = rsa_aes_utils.generate_rsa_keypair()
        self.session_key = None
        self.received_messages = []

    def get_public_key(self):
        return self.public_key

    #Create and send session key
    def create_and_send_session_key(self, recipient_public_key):
        self.session_key = rsa_aes_utils.generate_session_key()     #First generates AES key
        print(f"[{self.name}] AES Session Key generated: {self.session_key.hex()}")

        encrypted_key = rsa_aes_utils.encrypt_rsa(recipient_public_key, self.session_key)       #Encryprte key with recipient's public key.
        signature = rsa_aes_utils.sign_data(self.private_key, encrypted_key)        #sign the encrypted packet with own private key. This is for authentication
        return encrypted_key, signature     #Then return created encrypted key and signature

    # Receive and verify session key
    def receive_session_key(self, sender_public_key, encrypted_key, signature):

        is_valid = rsa_aes_utils.verify_signature(sender_public_key, encrypted_key, signature)      #Verify signature is valid?
        if not is_valid:
            print(f"[{self.name}] ERROR: Invalid signature. ")      #if it  is not valid send an error.
            return False
        else:
            print(f"\033[92m[{self.name}] Signature verified. Sender is authenticated.\033[0m")        #If it is valid signature verified and also sender is authenticated.
        time.sleep(2)

        # 2. Decrypt key with using own private key.
        try:
            self.session_key = rsa_aes_utils.decrypt_rsa(self.private_key, encrypted_key)
            print(f"[{self.name}] Session Key successfully decrypted: {self.session_key.hex()}")
            return True
        #If session key can't decrypt it throws error.
        except Exception as e:
            print(f"[{self.name}] Decryption error: {e}")
            return False

    #
    def send_encrypted_message(self, message, mode):
        if not self.session_key:
            raise ValueError("No Session Key found! Perform RSA key exchange first.")

        ciphertext, nonce, tag = rsa_aes_utils.encrypt_aes(self.session_key, message, mode)
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "mode": mode
        }

    def receive_encrypted_message(self, packet):
        if not self.session_key:
            raise ValueError("No Session Key found!")

        plaintext = rsa_aes_utils.decrypt_aes(
            self.session_key,
            packet["ciphertext"],
            packet["nonce"],
            packet["mode"],
            packet.get("tag")
        )
        return plaintext