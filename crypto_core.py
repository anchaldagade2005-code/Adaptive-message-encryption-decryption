from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Define the AES key size (256 bits = 32 bytes)
KEY_SIZE = 32

def generate_key_and_nonce():
    """Generates a secure random 256-bit AES key and a 12-byte Nonce."""
    # AES-256 Key (32 bytes)
    key = os.urandom(KEY_SIZE)
    # Nonce for GCM (12 bytes is standard)
    nonce = os.urandom(12)
    return key, nonce

def encrypt_message(key, nonce, plaintext):
    """Encrypts plaintext using AES-256 GCM mode."""
    # 1. Setup the cipher object
    cipher = Cipher(
        algorithms.AES(key), 
        modes.GCM(nonce), 
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # 2. Encrypt the data
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    
    # 3. Get the authentication tag (crucial for integrity check)
    tag = encryptor.tag
    
    # Return all necessary components for decryption
    return ciphertext, tag

def decrypt_message(key, nonce, ciphertext, tag):
    """Decrypts ciphertext and verifies integrity using the tag."""
    # 1. Setup the cipher object with the received tag
    cipher = Cipher(
        algorithms.AES(key), 
        modes.GCM(nonce, tag), 
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # 2. Decrypt the data
    # The 'finalize()' step will automatically check the integrity using the tag
    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext_bytes.decode()


# --- DEMONSTRATION ---
if __name__ == "__main__":
    
    # 1. Sender (A) generates the key and nonce for the message
    session_key, nonce = generate_key_and_nonce()
    
    original_message = "this is payal reporting from sector 47"
    
    print(f"Original Message: {original_message}")
    print("-" * 30)

    # 2. Sender (A) encrypts the message
    ciphertext, tag = encrypt_message(session_key, nonce, original_message)
    
    # In a real app, A would wrap the session_key using B's Public Key,
    # and send the base64-encoded versions of ciphertext, tag, nonce, and wrapped_key.
    
    print(f"Key (Hex): {session_key.hex()}")
    print(f"Nonce (Base64): {base64.b64encode(nonce).decode()}")
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Tag (Base64): {base64.b64encode(tag).decode()}")
    print("-" * 30)
    
    # 3. Receiver (B) receives the bundle and decrypts the session_key (not shown here)
    # 4. Receiver (B) decrypts the message using the recovered key, nonce, and tag
    try:
        decrypted_message = decrypt_message(session_key, nonce, ciphertext, tag)
        print(f"Decrypted Message: {decrypted_message}")
    except Exception as e:
        print(f"Decryption FAILED! Message integrity compromised: {e}")