#If code gives an error you may don't have pycryptodome library.
#First you should write "pip install pycryptodome" to download library in terminal.
from user import User
import time

# This function our print function for our main titles.
def print_separator(title=""):
    print(f"{title}")


def main():
    print_separator("Secure Communication Project (RSA + AES)")

    #Create Users Alice and Bob
    alice = User("Alice")
    bob = User("Bob")

    # RSA key exchange between usrers.
    print_separator(f"RSA Key Exchange Between {alice.name} & {bob.name}")
    print(f"{alice.name} is initiating a secure channel with {bob.name}...")
    time.sleep(3)       # These time.sleep lines are just simply to improve readability during the demo.

    # Alice prepares the key (Encrypt + Sign)
    # Alice uses Bob's Public Key to encrypt and her Private Key to sign
    enc_key_packet, signature = alice.create_and_send_session_key(bob.get_public_key())


    print(f"\n[Network] Transmitting Encrypted Packet: {enc_key_packet.hex()}")
    print(f"[Network] Transmitting Digital Signature: {signature.hex()}")
    time.sleep(2)

    # Bob receives packet, verifies signature, and decrypts key
    success = bob.receive_session_key(alice.get_public_key(), enc_key_packet, signature)

    if not success:
        print("\033[91mRSA key exchange FAILED! Terminating program.\033[0m")
        return

    print("\n\033[92mA SECURE CONNECTION HAS BEEN ESTABLISHED BETWEEN TWO USERS!\033[0m")
    time.sleep(5)

    # I can't make decision to which AES modes should I chose. Then I select GCM and CTR and compare both of it
    while True:
        print("="*60 + "\n")
        print("Select Encryption Mode:")
        print("[1] AES-GCM")
        print("[2] AES-CTR")
        print("[Q] Exit")

        choice = input("Your choice: ").upper()

        mode = "GCM" if choice == "1" else "CTR" if choice == "2" else None     #If user selects 1 the mode would be GCM, if suer selects 2 mode would be CTR.
        if choice == "Q":       #If user selects Q, the programme closes
            break

        if not mode:
            print("Invalid selection!")
            continue

        print(f"\n{mode} Mode Selected")
        msg_text = input(f"\033[96mEnter message from {alice.name} to {bob.name}: \033[0m")        #

        # Alice encrypte her message for sending to Bob.
        packet = alice.send_encrypted_message(msg_text, mode=mode)

        print(f"\n[{alice.name}] Encrypting message in {mode}...")
        print(f"Ciphertext: {packet['ciphertext'].hex()}")
        if mode == "GCM":
            print(f"Auth Tag:   {packet['tag'].hex()}")

        # This is our Man-in-the-Middle Simulation. These are for the challenge task.
        # We allow the user to corrupt the packet to demonstrate GCM vs CTR behavior
        while True:
            mitm = input("\n\033[96m[Challenge] Corrupt message during transmission? (yes/no): \033[0m").upper()
            if mitm == "YES":
                print("\033[91m[Hacker] Intercepting and modifying packet data...\033[0m")
                time.sleep(2)
                # The hacker intercepts and modifies the packet data.
                # To change the encrypted text, we reversed the bits in the last byte of the encrypted text.
                original_cipher = bytearray(packet["ciphertext"])
                original_cipher[-1] = original_cipher[-1] ^ 0xFF
                packet["ciphertext"] = bytes(original_cipher)
                break
            elif mitm == "NO":
                break
            else:
                print("Invalid selection!")
                continue


        # Bob decrypts
        print(f"\n[{bob.name}] Receiving and decrypting...")
        decrypted_msg = bob.receive_encrypted_message(packet)
        time.sleep(1)
        print(f"[{bob.name}] Incoming Message ({packet['mode']}): \033[92m{decrypted_msg}\033[0m")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()