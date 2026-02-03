from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher, low_level, extract_parameters # Final correct imports
from argon2.exceptions import VerifyMismatchError 
import os
import base64
from typing import Tuple, Dict, Any, Union

# --- GLOBAL CONSTANTS ---
KEY_SIZE = 32 # AES-256 key size in bytes
PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 4096 # Defense-grade RSA key size


# =========================================================================
# I. KEY DERIVATION FUNCTIONS (Master Key Generation)
# =========================================================================
# Global object for Argon2 configuration (cost parameters for security)
PH = PasswordHasher(
    time_cost=3,      
    memory_cost=65536,  
    parallelism=4,      
    hash_len=32,      
    salt_len=16       
)

def hash_password(password: str) -> str:
    """Creates a secure Argon2 hash (stored hash string) from the user's password."""
    return PH.hash(password)

# ... (inside your existing code, replace the body of the function below) ...

def verify_and_derive_key(hash_string: str, password: str) -> bytes:
    """
    Verifies the password against the stored hash and derives the 32-byte Master Key (K_M).
    Raises VerifyMismatchError if the password is wrong.
    """
    # 1. Verify the password first. This raises VerifyMismatchError if incorrect.
    PH.verify(hash_string, password)
    
    # 2. Extract Salt and Parameters directly from the hash string (Robust Parsing)
    parts = hash_string.split('$')
    
    # Extract Parameters (index 3 contains m=..., t=..., p=...)
    param_string = parts[3]
    params = {}
    for item in param_string.split(','):
        key, value = item.split('=')
        # Map to the C-binding names used by low_level.hash_secret_raw
        if key == 't': params['t_cost'] = int(value)
        if key == 'm': params['m_cost'] = int(value)
        if key == 'p': params['p_cost'] = int(value)

    # Extract Salt (index 4 is the base64 salt)
    salt_base64 = parts[4]
    
    # *** THE CRUCIAL BASE64 FIX: Use urlsafe_b64decode and add padding if necessary ***
    # Base64 strings must be padded with '=' to be a multiple of 4 in length.
    padding_needed = len(salt_base64) % 4
    if padding_needed != 0:
        salt_base64 += '=' * (4 - padding_needed)

    # Now decode using the URL-safe method, which handles '+' and '/' characters better
    salt_bytes = base64.urlsafe_b64decode(salt_base64)
    # *** END OF FIX ***
    
    # 3. Derive the Master Key bytes (K_M) using the extracted parameters and salt.
    derived_key_bytes = low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt_bytes,
        time_cost=params['t_cost'],
        memory_cost=params['m_cost'],
        parallelism=params['p_cost'],
        hash_len=32,
        # Determine the Argon2 type (i or id) from the hash string header (parts[1])
        type=low_level.Type.ID if parts[1] == 'argon2id' else low_level.Type.I
    )
    return derived_key_bytes


   



# =========================================================================
# II. AES GCM SYMMETRIC CRYPTOGRAPHY (Message Secrecy & Integrity)
# =========================================================================

def generate_key_and_nonce() -> Tuple[bytes, bytes]:
    """Generates a secure random 256-bit AES key (K_S) and a 12-byte Nonce (IV)."""
    key = os.urandom(KEY_SIZE)
    nonce = os.urandom(12) 
    return key, nonce

def encrypt_message(key: bytes, nonce: bytes, plaintext: str) -> Tuple[bytes, bytes]:
    """Encrypts plaintext using AES-256 GCM mode."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag # The tamper-proof seal
    
    return ciphertext, tag

def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    """Decrypts ciphertext and verifies integrity using the tag."""
    # The GCM mode checks the tag integrity in the finalize() step
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext_bytes.decode('utf-8')


# =========================================================================
# III. RSA ASYMMETRIC CRYPTOGRAPHY (Key Exchange & Identity)
# =========================================================================

def generate_rsa_key_pair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates a secure, defense-grade 4096-bit RSA Private Key and Public Key."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_keys(private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey, master_key_bytes: bytes) -> Tuple[bytes, bytes]:
    """Serializes and encrypts the private key using the Master Key bytes (K_M)."""
    
    # Private Key: Encrypted using the derived Master Key bytes (K_M)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # K_M is used here to secure the Private Key file on disk.
        encryption_algorithm=serialization.BestAvailableEncryption(master_key_bytes), 
    )

    # Public Key: Plaintext, for sharing
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private, pem_public

def load_private_key_from_pem(pem_private_key_bytes: bytes, master_key_bytes: bytes) -> rsa.RSAPrivateKey:
    """Loads the encrypted private key, requiring the derived Master Key bytes (K_M) to unlock it."""
    return serialization.load_pem_private_key(
        pem_private_key_bytes,
        # K_M is used here to unlock the Private Key into memory.
        password=master_key_bytes, 
        backend=default_backend()
    )

def wrap_session_key(session_key: bytes, recipient_public_key: rsa.RSAPublicKey) -> bytes:
    """Encrypts the symmetric session key (K_S) using the recipient's public key (RSA OAEP)."""
    return recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def unwrap_session_key(wrapped_key: bytes, receiver_private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypts the wrapped symmetric key using the receiver's private key (RSA OAEP)."""
    return receiver_private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# =========================================================================
# --- END-TO-END DEMONSTRATION ---
# =========================================================================
if __name__ == "__main__":
    
    # --- SIMULATE USER LOGIN DATA ---
    USER_PASSWORD = "MyUltraSecureDefensePass123!" # What the user types on the login screen
    
    # 1. SIMULATE REGISTRATION: Hash the password once and save the hash string.
    ALICE_STORED_HASH = hash_password(USER_PASSWORD)
    BOB_STORED_HASH = hash_password(USER_PASSWORD) 
    
    print("--- 1. SYSTEM SETUP: Generating Permanent Keys ---")
    
    # A. SIMULATE BOB'S LOGIN: Derive the Master Key (K_M) from the password
    try:
        # This is the slow, computationally expensive step (Master Key Derivation)
        BOB_MASTER_KEY_BYTES = verify_and_derive_key(BOB_STORED_HASH, USER_PASSWORD)
        print(f"[Master Key Derivation Successful] Key size: {len(BOB_MASTER_KEY_BYTES)} bytes.")
    except VerifyMismatchError:
        print("[FATAL ERROR] Master Password failed verification. Program halted.")
        exit()

    # B. Generate the RSA Keys and encrypt Private Key with the derived K_M
    alice_priv, alice_pub = generate_rsa_key_pair()
    bob_priv, bob_pub = generate_rsa_key_pair()
    
    # The Private Key is encrypted before "saving to disk" using the Master Key bytes (K_M)
    alice_priv_pem, alice_pub_pem = serialize_keys(alice_priv, alice_pub, BOB_MASTER_KEY_BYTES)
    bob_priv_pem, bob_pub_pem = serialize_keys(bob_priv, bob_pub, BOB_MASTER_KEY_BYTES)
    
    # Load Bob's Public Key for Alice to use
    bob_public_key = serialization.load_pem_public_key(bob_pub_pem, backend=default_backend())

    # ---------------------------------------------------------------------
    # 2. SENDER (ALICE) PROCESS: Encrypts Message and Key
    # ---------------------------------------------------------------------
    print("\n--- 2. ALICE SENDS: ENCRYPT MESSAGE AND KEY WRAP ---")
    
    session_key, nonce = generate_key_and_nonce()
    original_message = "ALERT: Enemy assets detected at grid coordinate B-4."

    # Encryption (AES-256 GCM)
    ciphertext, tag = encrypt_message(session_key, nonce, original_message)
    
    # Key Wrapping (RSA OAEP)
    wrapped_key = wrap_session_key(session_key, bob_public_key)

    print(f"Original Message: {original_message}")
    print(f"Size of Ciphertext: {len(ciphertext)} bytes")
    print(f"Size of Wrapped Key: {len(wrapped_key)} bytes")
    
    secure_bundle = {
        'wrapped_key': base64.b64encode(wrapped_key).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode(),
        'nonce': base64.b64encode(nonce).decode()
    }

    # ---------------------------------------------------------------------
    # 3. RECEIVER (BOB) PROCESS: Decrypts Key and Message
    # ---------------------------------------------------------------------
    print("\n--- 3. RECEIVER (BOB) RECEIVES: KEY UNWRAP AND DECRYPT ---")
    
    # A. Bob unlocks his Private Key using the derived Master Key (K_M)
    bob_private_key = load_private_key_from_pem(bob_priv_pem, BOB_MASTER_KEY_BYTES)
    
    # B. Key Unwrapping (RSA OAEP)
    received_wrapped_key = base64.b64decode(secure_bundle['wrapped_key'])
    received_session_key = unwrap_session_key(received_wrapped_key, bob_private_key)
    
    # C. Decryption and Integrity Check (AES-256 GCM)
    received_ciphertext = base64.b64decode(secure_bundle['ciphertext'])
    received_tag = base64.b64decode(secure_bundle['tag'])
    received_nonce = base64.b64decode(secure_bundle['nonce'])
    
    try:
        final_message = decrypt_message(
            received_session_key, 
            received_nonce, 
            received_ciphertext, 
            received_tag
        )
        print("\n[DECRYPTION SUCCESSFUL]")
        print(f"Final Decrypted Message: {final_message}")
    except Exception as e:
        print(f"[DECRYPTION FAILED] Message Integrity Check Failed: {e}")