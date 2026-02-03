from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# --- Key Generation Parameters ---
# Public Exponent (e): Standard value, typically 65537
PUBLIC_EXPONENT = 65537
# Key Size (n): 4096 bits is considered defense-grade strong
KEY_SIZE = 4096 
# Master Password: Used to encrypt and protect the Private Key file on disk
MASTER_PASSWORD = b"SecureMasterPassword123!" 


def generate_rsa_key_pair():
    """Generates a secure RSA Private Key."""
    # 1. Generate the private key
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    # The public key is derived from the private key
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key, password):
    """
    Serializes keys into formats suitable for storage/transmission.
    The Private Key is encrypted using the Master Key (password).
    """
    
    # --- 1. Serialize Private Key (Protected) ---
    # Encryption Method: Best Practice, modern PKCS8, uses AES-256-CBC
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        # This is where the Master Key concept is implemented:
        # The key is encrypted with AES-256 before being written to disk!
        encryption_algorithm=serialization.BestAvailableEncryption(password), 
    )

    # --- 2. Serialize Public Key (Unprotected - For Sharing) ---
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private, pem_public

# --- DEMONSTRATION ---
if __name__ == "__main__":
    
    print("--- Generating Alice's Key Pair ---")
    alice_priv, alice_pub = generate_rsa_key_pair()
    
    # In a real app, the password would be derived from the user's login password (Master Key concept)
    # Here, we use a simple byte string password for demonstration.
    alice_priv_pem, alice_pub_pem = serialize_keys(alice_priv, alice_pub, MASTER_PASSWORD)

    print("\n[SUCCESS] Key Pair Generated and Encrypted!")
    
    # -------------------------------------------------------------
    # Technical Check: What the stored files look like
    # -------------------------------------------------------------
    print("\n--- Alice's Encrypted PRIVATE Key (Secondary Key on disk) ---")
    print(alice_priv_pem.decode()[:200] + "...")
    # NOTE the 'ENCRYPTED PRIVATE KEY' header. This confirms the Master Key protection is applied.
    
    print("\n--- Alice's PUBLIC Key (Shared with Bob) ---")
    print(alice_pub_pem.decode()[:200] + "...")
    # NOTE the 'BEGIN PUBLIC KEY' header. This key is safe to share with others.