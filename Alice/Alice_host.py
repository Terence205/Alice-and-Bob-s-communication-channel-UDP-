# Step 1: B → A: “Bob”
# Bob (Client) sends his identity ("Bob") to Alice (Host).
# Purpose: To let Alice know who is trying to connect.
# Step 2: A → B: E(H(PW), p, g, ga mod p)
# Alice responds with Diffie-Hellman parameters (p, g) and her public value (ga mod p), encrypted with the hashed password using RC4.
# Purpose: To securely send DH parameters so only someone with the correct password can decrypt and use them.
# Step 3: B → A: E(H(PW), gb mod p)
# Bob sends his Diffie-Hellman public value (gb mod p), encrypted with the hashed password using RC4.
# Purpose: To allow Alice to compute the shared session key.
# Step 4: A → B: E(K, NA)
# Alice generates a nonce (NA), encrypts it with the session key (K), and sends it to Bob.
# Purpose: To prove Alice knows the session key and to initiate mutual authentication.
# Step 5: B → A: E(K, NA+1, NB)
# Bob increments Alice’s nonce (NA+1), generates his own nonce (NB), and sends both encrypted with the session key.
# Purpose: To prove Bob knows the session key and to challenge Alice with his own nonce.
# Step 6: A → B: E(K, NB+1) or “Login Failed”
# Alice increments Bob’s nonce (NB+1) and sends it back encrypted with the session key, or sends “Login Failed” if authentication fails.
# Purpose: To prove Alice knows the session key and to complete mutual authentication.

import socket
import hashlib
import ast
import os
from Crypto.Cipher import ARC4
import math
from cryptography.hazmat.primitives.asymmetric import dh

sock= socket.socket(family= socket.AF_INET, type= socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 4112))
login_bool= False

pw= "topsecretpass"
print("Alice is running...")

def safe_increment(nonce):
    nonce_int = int.from_bytes(nonce, 'big')
    max_val = (1 << (8 * len(nonce))) - 1
    if nonce_int == max_val:
        print("nonce's byte overflow!")
        return safe_increment(os.urandom(len(nonce)))  # get new nonce on overflow
    return (nonce_int + 1).to_bytes(len(nonce), 'big')

def send_message(sock, K, message, address):
    """
    Encrypts and authenticates a message using the shared key K.
    Format: E(K, M || H(K||M||K))
    """
    # Compute hash 
    hash_value = hashlib.sha1((K + message + K).encode("utf-8")).digest()  # H(K||M||K)
    plaintext = message.encode() + hash_value  # M || hash

    # Encrypt with RC4
    K= (int(K)).to_bytes(int(K).bit_length()+ 7// 8, 'big')  # Ensure K is in bytes
    hash_K= hashlib.sha1(K).digest()  
    cipher = ARC4.new(hash_K)
    ciphertext = cipher.encrypt(plaintext)

    # Send ciphertext
    sock.sendto(ciphertext, address)
    print(f"Sent (encrypted): {message}")

def receive_message(sock, K):
    """
    Decrypts and verifies a message using the shared key K.
    Returns the decrypted message or None if verification fails.
    """
    ciphertext, address = sock.recvfrom(4096)
    K_msg= K

    # Decrypt with RC4
    K= (int(K)).to_bytes(int(K).bit_length()+ 7// 8, 'big')  # Ensure K is in bytes
    hash_K= hashlib.sha1(K).digest()  
    cipher = ARC4.new(hash_K)
    decrypted = cipher.decrypt(ciphertext)

    # Split into message and hash
    message = decrypted[:-20]  # M (all except last 20 bytes)
    received_hash = decrypted[-20:]  # Last 20 bytes = SHA-1 hash

    # Verify integrity
    computed_hash = hashlib.sha1(K_msg.encode("utf-8") + message + K_msg.encode("utf-8")).digest()  # H(K||M||K)
    # computed_hash = hashlib.sha1(K + message + K).digest()  # H(K||M||K)
    if received_hash == computed_hash:
        print(f"Received (decrypted): {message.decode()}")
        return message.decode()
    else:
        print("Error: Message authentication failed!")
        return None
    
def secure_chat(sock, K, is_host=True, address=None):
    """
    Handles the encrypted chat loop.
    - is_host: True for Alice (Host), False for Bob (Client).
    - peer_addr: (IP, port) of the other party.
    """
    try:
        while True:
            # Send messages
            message = input("'exit' to quit\nSend message: ")
            if message.lower() == "exit":
                print("Host shutting down...")
                break
            send_message(sock, K, message, address)

            # Receive messages (timeout to avoid blocking)
            sock.settimeout(2.0)
            try:
                received = receive_message(sock, K)
                if received is None:
                    break  # Terminate on auth failure
            except socket.timeout:
                pass  # No message received

    finally:
        sock.close()

while True:
    if login_bool== False:
        try:
            dh_params_for_txt= dh.generate_parameters(generator= 2, key_size= 1024)  # Generate DH parameters for the file
            with open("C:\\Users\\User\\Desktop\\Terence\\network security\\A1\\Alice\\information.txt", "w") as file:
                file.write(f"{dh_params_for_txt.parameter_numbers().p}, {dh_params_for_txt.parameter_numbers().g}, {hashlib.sha1(pw.encode('utf-8')).digest()}")

            message, address= sock.recvfrom(4096)  # Wait for Bob message for potential quit
            if message.decode("utf-8").lower() == "close":
                print("Host shutting down...")
                sock.close()
                login_bool= False


            elif message.decode("utf-8").lower() == "continue":
                # read from file, read p, g, password hash
                with open("C:\\Users\\User\\Desktop\\Terence\\network security\\A1\\Alice\\information.txt", "r") as file:
                    p, g, pw_hash= file.read().strip().split(", ")

            # 1. B → A: “Bob”
            data, address= sock.recvfrom(4096)
            print(data.decode("utf-8")) 

            # 2. A → B: E(H(PW), p, g, ga mod p)
            utf8PW= pw.encode("utf-8")
            pw_hash= ast.literal_eval(pw_hash)  # Ensure PW_hash is in bytes
            # PW_hash= hashlib.sha1(utf8PW).digest()
            a= dh_params_for_txt.generate_private_key()
            Alices_public_key= pow(int(g), a.private_numbers().x, int(p))
            # I demonstrated 2 ways to getting Alice's public key, to display a better understanding of DH
            # Alternatively can use the following line as well:
            Alices_public_key_showcase= a.private_numbers().public_numbers.y
            # if Alices_public_key == Alices_public_key_showcase:
                # print("Alices public key is: ", Alices_public_key) #True, Alices public key is:  68679276358178...

            # RC4 encryption using H(PW)
            plain_text= f"{pw_hash}, {p}, {g}, {Alices_public_key}"
            cipher= ARC4.new(pw_hash)
            cipher_text= cipher.encrypt(plaintext= plain_text.encode("utf-8"))

            # Send the cipher text to bob
            sock.sendto(cipher_text, address)

            # 3. B → A: E(H(PW), gb mod p)
            message, address= sock.recvfrom(4096)
            decrypted_text= cipher.decrypt(message)

            pw_hash, Bobs_public_key= decrypted_text.decode("utf-8").split(", ")
            # if pw_hash == str(pw_hash): # Confirming that the hash matches
            #     print("pw_hash in str literal: " + pw_hash)
                # print("Decrypted message from Bob:", decrypted_text.decode("utf-8"))  # This will show the decrypted message from Bob
            pw_hash= ast.literal_eval(pw_hash)  # Ensure pw_hash is in bytes

            K= pow(int(Bobs_public_key), a.private_numbers().x, int(p))
            # print("Shared key: ", K)

            # 4. A → B: E(K, NA)
            nonce_Alice= os.urandom(16) # Generate a nonce for Alice
            plain_text= f"{K}, {nonce_Alice}"
            cipher_text= cipher.encrypt(plaintext=plain_text.encode("utf-8"))
            sock.sendto(cipher_text, address)

            # 6. A → B: E(K, NB+1) or “Login Failed”
            message, address= sock.recvfrom(4096)
            decrypted_text= cipher.decrypt(message).decode("utf-8")
            K, nonce_Alice_inc, nonce_Bob= decrypted_text.split(", ")
            nonce_Alice_inc= ast.literal_eval(nonce_Alice_inc)
            nonce_Bob= ast.literal_eval(nonce_Bob)
            nonce_Alice= safe_increment(nonce= nonce_Alice) # return in bytes
            if str(nonce_Alice) == str(nonce_Alice_inc):
                plain_text= f"{K}, {safe_increment(nonce_Bob)}"
                cipher_text= cipher.encrypt(plaintext= plain_text.encode("utf-8"))
                sock.sendto(cipher_text, address)
                
            else: 
                sock.sendto("login failed".encode("utf-8"), address)

            # for terminate
            message, address= sock.recvfrom(4096)
            if message.decode("utf-8")== "login failed":
                print("Host shutting down...")
                sock.close()
                login_bool= False
                break
            else:
                login_bool= True
                print("Handshake success!")




            # message= sock.recv(4096)
            # if message== "success":
            #     login_bool= True

        except KeyboardInterrupt:
            print("\nHost shutting down...")

        except Exception as e:
            print(f"Error: {e}")

    elif login_bool== True:

        try:
            secure_chat(sock, K, is_host=True, address=address)
            break

        except KeyboardInterrupt:
            print("\nHost shutting down...")
            break


sock.close()
