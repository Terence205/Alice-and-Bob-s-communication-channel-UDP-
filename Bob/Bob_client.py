import socket
import hashlib
import math
import os
import ast
from Crypto.Cipher import ARC4
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

client_sock= socket.socket(family= socket.AF_INET, type= socket.SOCK_DGRAM)

pw= "topsecretpass"
login_bool= False

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
    # bit_length = (int(K).bit_length() + 7) // 8  # Ensure K is in bytes
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
                print("Client shutting down...")
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
    if login_bool == False:
        try:
            inputs= input("'exit' to quit \n Enter password: ")
            if inputs.lower() == "quit":
                print("Client shutting down...")
                client_sock.sendto("close".encode("utf-8"), ("127.0.0.1", 4112))
                client_sock.close()
            elif inputs.lower() == pw:
                client_sock.sendto("continue".encode("utf-8"), ("127.0.0.1", 4112))
                login_bool= False
            else:
                print("Incorrect password")
                client_sock.sendto("close".encode("utf-8"), ("127.0.0.1", 4112))
                client_sock.close()
                

            # 1. B → A: “Bob”
            bobs_message= "Bob".encode("utf-8")
            client_sock.sendto(bobs_message, ("127.0.0.1", 4112))

            # 2. A → B: E(H(PW), p, g, ga mod p)
            utf8PW= pw.encode("utf-8")
            hash_pw= hashlib.sha1(utf8PW).digest()
            cipher= ARC4.new(hash_pw)
            data, address= client_sock.recvfrom(4096)
            decrypted_text= cipher.decrypt(data)
            deconcatenated_decrypted_text = decrypted_text.decode("utf-8").split(", ")
            # if deconcatenated_decrypted_text[0] == str(hash_pw): # Check if the hash matches
            #     print("Decrypted text from Alice:", decrypted_text.decode("utf-8")) # Will be printed if decryption is successful AND the H(PW) is the same

            # 3. B → A: E(H(PW), gb mod p)
            dh_params= dh.DHParameterNumbers(g= int(deconcatenated_decrypted_text[2]), p=int(deconcatenated_decrypted_text[1])).parameters()
            b = dh_params.generate_private_key()
            Bobs_public_key= pow(int(deconcatenated_decrypted_text[2]), b.private_numbers().x, int(deconcatenated_decrypted_text[1]))
            plain_text= f"{hash_pw}, {Bobs_public_key}"
            cipher_text= cipher.encrypt(plaintext= plain_text.encode("utf-8"))
            K= pow(int(deconcatenated_decrypted_text[3]), b.private_numbers().x, int(deconcatenated_decrypted_text[1]))
            # print("Shared key: ", K)

            # Send to ALice
            client_sock.sendto(cipher_text, address)

            # 4. A → B: E(K, NA)
            message, address= client_sock.recvfrom(4096)
            decrypted_text= cipher.decrypt(message).decode("utf-8")
            K, nonce_Alice= decrypted_text.split(", ")


            # 5. B → A: E(K, NA+1, NB)
            nonce_Bob= os.urandom(16)
            nonce_Alice= ast.literal_eval(nonce_Alice)
            nonce_Alice= safe_increment(nonce= nonce_Alice) # return in bytes
            plain_text= f"{K}, {nonce_Alice}, {nonce_Bob}"
            encrypted_text= cipher.encrypt(plaintext=plain_text.encode("utf-8"))
            client_sock.sendto(encrypted_text, address)

            #6. A → B: E(K, NB+1) or “Login Failed”
            message, address= client_sock.recvfrom(4096)
            decrypted_text= cipher.decrypt(message).decode()
            K, nonce_Bob_inc= decrypted_text.split(", ")
            if K == "login failed":
                print("Client shutting down...")
                client_sock.close()
                login_bool= False
                break
            else:
                # message, address= client_sock.recvfrom(4096)
                # K, nonce_Bob_inc= decrypted_text.split(", ")
                nonce_Bob_inc= ast.literal_eval(nonce_Bob_inc)
                nonce_Bob= safe_increment(nonce_Bob)
                if nonce_Bob == nonce_Bob_inc:
                    client_sock.sendto("login success".encode("utf-8"), address)
                    login_bool= True
                else: 
                    client_sock.sendto("login failed".encode("utf-8"), address)





            # if handshake successful
            # client_sock.sendto("success".encode("utf-8"), address)
            # login_bool= True

        except KeyboardInterrupt:
            print("\nClient shutting down...")
            break

        except Exception as e:
            print(f"Error: {e}")

    elif login_bool == True:
        try:
            secure_chat(client_sock, K, is_host=False, address=address)
            break
        
        except KeyboardInterrupt:
            print("\nClient shutting down...")
            break
