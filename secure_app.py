import tkinter as tk
from tkinter import messagebox, scrolledtext
import os
import base64
from typing import Tuple, Dict, Any, Union
from datetime import datetime

# --- Corrected Crypto Imports ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher, low_level
from argon2.exceptions import VerifyMismatchError 


# =========================================================================
# I. CRYPTO CORE (CONSOLIDATED)
# =========================================================================

# --- GLOBAL CONSTANTS ---
KEY_SIZE = 32 # AES-256 key size in bytes
PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 4096 # Defense-grade RSA key size


# --- KEY DERIVATION FUNCTIONS (Master Key Generation) ---
PH = PasswordHasher(
    time_cost=3,      
    memory_cost=65536,  
    parallelism=4,      
    hash_len=32,      
    salt_len=16       
)

# 1. FIX: These must be OUTSIDE the class for the setup function to find them.
def hash_password(password: str) -> str:
    """Creates a secure Argon2 hash (stored hash string) from the user's password."""
    return PH.hash(password)

def verify_and_derive_key(hash_string: str, password: str) -> bytes:
    """
    Verifies the password against the stored hash and derives the 32-byte Master Key (K_M).
    """
    PH.verify(hash_string, password)
    
    parts = hash_string.split('$')
    param_string = parts[3]
    params = {}
    for item in param_string.split(','):
        key, value = item.split('=')
        if key == 't': params['t_cost'] = int(value)
        if key == 'm': params['m_cost'] = int(value)
        if key == 'p': params['p_cost'] = int(value)

    salt_base64 = parts[4]
    
    # Argon2 URL-safe base64 is sometimes unpadded, must be handled manually
    padding_needed = len(salt_base64) % 4
    if padding_needed != 0:
        salt_base64 += '=' * (4 - padding_needed)

    salt_bytes = base64.urlsafe_b64decode(salt_base64)
    
    derived_key_bytes = low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt_bytes,
        time_cost=params['t_cost'],
        memory_cost=params['m_cost'],
        parallelism=params['p_cost'],
        hash_len=32,
        type=low_level.Type.ID if parts[1] == 'argon2id' else low_level.Type.I
    )
    return derived_key_bytes


# --- AES GCM SYMMETRIC CRYPTOGRAPHY ---

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
    tag = encryptor.tag 
    
    return ciphertext, tag

def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> str:
    """Decrypts ciphertext and verifies integrity using the tag."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext_bytes.decode('utf-8')


# --- RSA ASYMMETRIC CRYPTOGRAPHY ---

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
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(master_key_bytes), 
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_private, pem_public

def load_private_key_from_pem(pem_private_key_bytes: bytes, master_key_bytes: bytes) -> rsa.RSAPrivateKey:
    """Loads the encrypted private key, requiring the derived Master Key bytes (K_M) to unlock it."""
    return serialization.load_pem_private_key(
        pem_private_key_bytes,
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
# II. TKINTER GUI APPLICATION CLASS
# =========================================================================

# --- Global State for Demo (Simulates storage on disk) ---
USER_DATA = {
    'alice': {'stored_hash': None, 'public_key_pem': None, 'private_key_pem': None},
    'bob': {'stored_hash': None, 'public_key_pem': None, 'private_key_pem': None},
}

class SecureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Defense Message System - Secure Crypto Core")
        self.geometry("1200x800") 

        # --- THEME COLORS (DASHBOARD VIBE) ---
        self.bg_color = "#0A0A0A"    # Near Black
        self.fg_color = "#00FF00"    # Bright Neon Green for primary text
        self.accent_color = "#008800" # Darker Green for borders/accents
        self.entry_bg = "#1A1A1A"    # Very Dark Grey for input fields
        self.button_bg = "#004400"   # Dark Green for button background
        self.button_fg = "#00FF00"   # Neon Green for button text
        self.header_font = ("Consolas", 24, "bold") 
        self.label_font = ("Consolas", 12)
        self.entry_font = ("Consolas", 12)
        self.button_font = ("Consolas", 12, "bold")
        # --------------------

        self.config(bg=self.bg_color) 

        # State variables for the logged-in user
        self.current_username = None
        self.master_key = None 
        self.private_key = None 
        self.public_key_pem = None 
        self.log_text = None 
        
        self.show_login_screen()

    def apply_theme_to_widget(self, widget_type, widget, **kwargs):
        if widget_type == 'label':
            widget.config(bg=self.bg_color, fg=self.fg_color, font=self.label_font, **kwargs)
        elif widget_type == 'entry':
            widget.config(bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, font=self.entry_font, **kwargs) 
        elif widget_type == 'button':
            widget.config(bg=self.button_bg, fg=self.button_fg, font=self.button_font, relief=tk.FLAT, activebackground=self.accent_color, activeforeground=self.bg_color, **kwargs)
        elif widget_type == 'header':
            widget.config(bg=self.bg_color, fg=self.fg_color, font=self.header_font, **kwargs)
        elif widget_type == 'text': 
            widget.config(bg=self.entry_bg, fg=self.fg_color, insertbackground=self.fg_color, font=self.entry_font, **kwargs)
        else:
            widget.config(bg=self.bg_color, fg=self.fg_color, font=self.label_font, **kwargs)

    def get_theme_kwargs(self, widget_type):
        if widget_type == 'label':
            return {'bg': self.bg_color, 'fg': self.fg_color, 'font': self.label_font}
        if widget_type == 'button':
            return {'bg': self.button_bg, 'fg': self.button_fg, 'font': self.button_font, 'relief': tk.FLAT, 'activebackground': self.accent_color, 'activeforeground': self.bg_color}
        return {}
        
    def log_activity(self, message):
        """Adds a timestamped message to the activity log."""
        if not self.log_text: return
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"{timestamp} {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')


    # --- LOGIN SCREEN METHODS ---

    def show_login_screen(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        login_frame = tk.Frame(self, bg=self.bg_color)
        login_frame.pack(expand=True)

        header_label = tk.Label(login_frame, text="Secure Terminal Login")
        self.apply_theme_to_widget('header', header_label)
        header_label.pack(pady=20)
        
        username_label = tk.Label(login_frame, text="Username (alice/bob):")
        self.apply_theme_to_widget('label', username_label)
        username_label.pack(pady=5)
        self.user_entry = tk.Entry(login_frame, width=40)
        self.apply_theme_to_widget('entry', self.user_entry)
        self.user_entry.pack(pady=5)
        
        password_label = tk.Label(login_frame, text="Password:")
        self.apply_theme_to_widget('label', password_label)
        password_label.pack(pady=5)
        self.pass_entry = tk.Entry(login_frame, width=40, show="*")
        self.apply_theme_to_widget('entry', self.pass_entry)
        self.pass_entry.pack(pady=5)
        
        login_button = tk.Button(login_frame, text="Login / Unlock Key", command=self.attempt_login)
        self.apply_theme_to_widget('button', login_button)
        login_button.pack(pady=10)
        
        setup_button = tk.Button(login_frame, text="Setup New User (Generate Keys)", command=self.setup_new_user)
        self.apply_theme_to_widget('button', setup_button)
        setup_button.pack(pady=5)

    def setup_new_user(self):
        username = self.user_entry.get().lower()
        password = self.pass_entry.get()
        
        if not username or not password or username not in USER_DATA:
            messagebox.showerror("Error", "Enter a valid user (alice or bob) and password.")
            return

        try:
            # This calls the global function (FIX for Image b09203)
            stored_hash = hash_password(password)
            master_key_bytes = verify_and_derive_key(stored_hash, password)
            private_key, public_key = generate_rsa_key_pair()
            priv_pem, pub_pem = serialize_keys(private_key, public_key, master_key_bytes)
            
            # Save data
            USER_DATA[username]['stored_hash'] = stored_hash
            USER_DATA[username]['private_key_pem'] = priv_pem
            USER_DATA[username]['public_key_pem'] = pub_pem
            
            messagebox.showinfo("Success", f"User {username.capitalize()} setup complete. Keys generated and encrypted.")
            self.user_entry.delete(0, tk.END)
            self.pass_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Setup Failed", f"An error occurred during key generation: {e}")

    def attempt_login(self):
        username = self.user_entry.get().lower()
        password = self.pass_entry.get()
        
        if username not in USER_DATA or not USER_DATA[username]['stored_hash']:
            messagebox.showerror("Error", "User not found or keys not set up. Click 'Setup New User' first.")
            return

        try:
            stored_hash = USER_DATA[username]['stored_hash']
            self.master_key = verify_and_derive_key(stored_hash, password)
            
            priv_pem = USER_DATA[username]['private_key_pem']
            self.private_key = load_private_key_from_pem(priv_pem, self.master_key)
            self.public_key_pem = USER_DATA[username]['public_key_pem'].decode('utf-8')
            self.current_username = username.capitalize()

            messagebox.showinfo("Success", f"Welcome, {self.current_username}. Private Key Unlocked.")
            self.show_dashboard_screen()

        except VerifyMismatchError:
            messagebox.showerror("Login Failed", "Incorrect Password.")
        except Exception as e:
            # This is the point where the 'bad option' errors were raised.
            messagebox.showerror("Login Failed", f"Could not unlock Private Key: {e}")


    # --- DASHBOARD SCREEN METHODS ---
    
    def create_panel(self, parent, title, row, col, rowspan=1, columnspan=1):
        """Helper function to create a themed dashboard panel."""
        panel_frame = tk.LabelFrame(parent, text=title, bg=self.bg_color, fg=self.fg_color, 
                                     font=("Consolas", 14, "bold"), bd=3, relief=tk.SOLID, 
                                     padx=5, pady=5)
        # 2. FIX: Ensure all panel frames use GRID options only.
        panel_frame.grid(row=row, column=col, rowspan=rowspan, columnspan=columnspan, 
                         sticky="nsew", padx=10, pady=10)
        return panel_frame
    
    # 3. FIX: Clean, single, and fully correct dashboard definition (addresses all 'bad option' images)
    def show_dashboard_screen(self):
        for widget in self.winfo_children():
            widget.destroy()
        
        # --- Main Grid Layout ---
        self.grid_rowconfigure(1, weight=1) 
        self.grid_columnconfigure((0, 1, 2), weight=1) 
        
        # --- Dashboard Header (Row 0) ---
        header_frame = tk.Frame(self, bg=self.bg_color)
        header_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(10, 0))
        
        # Header contents use PACK within the header_frame
        tk.Label(header_frame, text=f"SECURE TERMINAL ACCESS: {self.current_username}",
                 bg=self.bg_color, fg=self.fg_color, font=self.header_font).pack(pady=5)
        
        self.status_label = tk.Label(header_frame, text="STATUS: OPERATIONAL", 
                                     bg=self.bg_color, fg=self.fg_color, font=("Consolas", 12))
        self.status_label.pack(pady=5)
        
        # --- Left Panel: System Control & Identity (Row 1, Column 0) ---
        control_panel = self.create_panel(self, "SYSTEM CONTROL & IDENTITY", 1, 0, rowspan=1)
        control_panel.grid_rowconfigure(1, weight=1)
        control_panel.grid_rowconfigure(3, weight=1)
        control_panel.grid_columnconfigure(0, weight=1)
        
        tk.Label(control_panel, text="YOUR PUBLIC KEY (Share)", **self.get_theme_kwargs('label')).grid(row=0, column=0, pady=5, padx=5, sticky='w')
        self.pub_key_display = scrolledtext.ScrolledText(control_panel, height=8, width=45)
        self.apply_theme_to_widget('text', self.pub_key_display)
        self.pub_key_display.insert("1.0", self.public_key_pem)
        self.pub_key_display.config(state='disabled')
        # All panel items use GRID options only: row, column, sticky, padx, pady
        self.pub_key_display.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
        
        tk.Label(control_panel, text="RECIPIENT PUBLIC KEY", **self.get_theme_kwargs('label')).grid(row=2, column=0, pady=(10, 5), padx=5, sticky='w')
        self.recipient_key_text = scrolledtext.ScrolledText(control_panel, height=8, width=45)
        self.apply_theme_to_widget('text', self.recipient_key_text)
        self.recipient_key_text.grid(row=3, column=0, padx=5, pady=5, sticky='nsew')

        tk.Button(control_panel, text="LOGOUT / WIPE SESSION", command=self.logout, **self.get_theme_kwargs('button')).grid(row=4, column=0, sticky='ew', padx=5, pady=15)
        
        # --- Center Panel: Message I/O (Row 1, Column 1) ---
        message_panel = self.create_panel(self, "SECURE MESSAGE I/O", 1, 1, rowspan=1)
        message_panel.grid_rowconfigure(1, weight=1)
        message_panel.grid_columnconfigure(0, weight=1)
        
        tk.Label(message_panel, text="DATA INPUT / OUTPUT (Plaintext or Bundle)", **self.get_theme_kwargs('label')).grid(row=0, column=0, pady=5, padx=5, sticky='w')
        self.message_input_text = scrolledtext.ScrolledText(message_panel, height=25, width=60)
        self.apply_theme_to_widget('text', self.message_input_text)
        self.message_input_text.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
        
        button_frame = tk.Frame(message_panel, bg=self.bg_color)
        # This frame is placed with GRID
        button_frame.grid(row=2, column=0, sticky="ew", pady=10, padx=5) 
        
        # The buttons inside this frame use GRID
        button_frame.grid_columnconfigure((0, 1), weight=1)
        tk.Button(button_frame, text="ENCRYPT & ENCODE", command=self.encrypt_and_encode, **self.get_theme_kwargs('button')).grid(row=0, column=0, sticky='ew', padx=(0, 5))
        tk.Button(button_frame, text="DECODE & DECRYPT", command=self.decode_and_decrypt, **self.get_theme_kwargs('button')).grid(row=0, column=1, sticky='ew', padx=(5, 0))
        
        # --- Right Panel: Status and Logs (Row 1, Column 2) ---
        log_panel = self.create_panel(self, "NETWORK & LOGS", 1, 2, rowspan=1)
        log_panel.grid_rowconfigure(3, weight=1)
        log_panel.grid_columnconfigure(0, weight=1)
        
        tk.Label(log_panel, text="[M-COST]: 65536 | [T-COST]: 3", **self.get_theme_kwargs('label')).grid(row=0, column=0, pady=5, padx=5, sticky='w')
        tk.Label(log_panel, text="[RSA-SIZE]: 4096-bit | [AES]: GCM-256", **self.get_theme_kwargs('label')).grid(row=1, column=0, pady=5, padx=5, sticky='w')
        
        tk.Label(log_panel, text="\n--- ACTIVITY LOG ---", **self.get_theme_kwargs('label')).grid(row=2, column=0, pady=(10, 5), padx=5, sticky='w')
        self.log_text = scrolledtext.ScrolledText(log_panel, height=20, width=40)
        self.apply_theme_to_widget('text', self.log_text)
        self.log_text.grid(row=3, column=0, padx=5, pady=5, sticky='nsew')
        self.log_activity("Secure shell loaded.")
        self.log_activity("Awaiting input...")

    # --- ENCRYPTION/DECRYPTION PLACEHOLDER METHODS ---
    
    def encrypt_and_encode(self):
        """Encrypts plaintext and bundles it for transfer."""
        plaintext = self.message_input_text.get("1.0", tk.END).strip()
        recipient_key_text = self.recipient_key_text.get("1.0", tk.END).strip()

        if not plaintext:
            messagebox.showerror("Error", "Message input is empty.")
            return

        if not recipient_key_text:
            messagebox.showerror("Error", "Recipient Public Key is missing.")
            self.log_activity("ENCRYPT FAILED: Recipient key missing.")
            return

        try:
            # 1. Load Recipient's Public Key (Check PEM format)
            recipient_public_key = serialization.load_pem_public_key(
                recipient_key_text.encode('utf-8'),
                backend=default_backend()
            )
            self.log_activity("Recipient Public Key loaded successfully.")

            # 2. Generate Symmetric Key (K_S) and Nonce
            session_key, nonce = generate_key_and_nonce()
            
            # 3. Encrypt the Message (using K_S)
            ciphertext, tag = encrypt_message(session_key, nonce, plaintext)
            
            # 4. Encrypt the Session Key (K_S) using RSA (Asymmetric Wrap)
            wrapped_key = wrap_session_key(session_key, recipient_public_key)

            # 5. Create the Transfer Bundle (Base64 Encode all binary parts)
            bundle_parts = [
                base64.b64encode(wrapped_key).decode('utf-8'),
                base64.b64encode(nonce).decode('utf-8'),
                base64.b64encode(tag).decode('utf-8'),
                base64.b64encode(ciphertext).decode('utf-8')
            ]
            
            encrypted_bundle = (
                "--- BEGIN ENCRYPTED BUNDLE ---\n"
                f"WRAP:{bundle_parts[0]}\n"
                f"IV:{bundle_parts[1]}\n"
                f"TAG:{bundle_parts[2]}\n"
                f"CTXT:{bundle_parts[3]}\n"
                "--- END ENCRYPTED BUNDLE ---"
            )

            # 6. Display the Bundle
            self.message_input_text.delete("1.0", tk.END)
            self.message_input_text.insert("1.0", encrypted_bundle)
            self.log_activity("SUCCESS: Encrypted bundle ready for transfer.")
            self.status_label.config(text="STATUS: ENCRYPTION SUCCESS", fg="#00FF00")

        except ValueError as e:
            # Catches MalformedFraming errors (Image b1fa5d)
            messagebox.showerror("Encryption Failed", f"Error during key load: Malformed Key. Ensure key is copied exactly: {e}")
            self.log_activity(f"ENCRYPT FAILED: Malformed key: {e}")
            self.status_label.config(text="STATUS: KEY ERROR", fg="red")
        except Exception as e:
            messagebox.showerror("Encryption Failed", f"An unexpected error occurred: {e}")
            self.log_activity(f"ENCRYPT FAILED: {e}")
            self.status_label.config(text="STATUS: FAILED", fg="red")
            
        """Placeholder for the primary encryption logic."""
        recipient_key_text = self.recipient_key_text.get("1.0", tk.END).strip()
        
        if not recipient_key_text:
            messagebox.showerror("Error", "Recipient Public Key is missing.")
            self.log_activity("ENCRYPT FAILED: Recipient key missing.")
            return

        try:
            # Check for PEM formatting issue (Addresses Image b1fa5d)
            recipient_public_key = serialization.load_pem_public_key(
                recipient_key_text.encode('utf-8'),
                backend=default_backend()
            )
            self.log_activity("Recipient Public Key loaded successfully.")
            
            # Placeholder for actual crypto logic
            self.message_input_text.delete("1.0", tk.END)
            self.message_input_text.insert("1.0", "--- BEGIN ENCRYPTED BUNDLE --- [Insert Encrypted Data Here] --- END ENCRYPTED BUNDLE ---")
            self.log_activity("SUCCESS: Encrypted bundle ready for transfer.")
            self.status_label.config(text="STATUS: ENCRYPTION SUCCESS", fg="#00FF00")

        except Exception as e:
            messagebox.showerror("Encryption Failed", f"Error during key load: {e}. Check for extra characters or incorrect format.")
            self.log_activity(f"ENCRYPT FAILED: {e}")
            self.status_label.config(text="STATUS: KEY ERROR", fg="red")

    def decode_and_decrypt(self):
        """Parses bundle, unwraps key, and decrypts message."""
        bundle_text = self.message_input_text.get("1.0", tk.END).strip()
        
        if not self.private_key:
            messagebox.showerror("Error", "Private Key not unlocked. Log in again.")
            self.log_activity("DECRYPT FAILED: Private Key unavailable.")
            return
        
        if "--- BEGIN ENCRYPTED BUNDLE ---" not in bundle_text:
            messagebox.showerror("Error", "Input is not a recognized encrypted bundle.")
            self.log_activity("DECRYPT FAILED: Invalid bundle format.")
            return

        try:
            # 1. Parse the Bundle
            parts = {}
            for line in bundle_text.split('\n'):
                if ":" in line:
                    key, val = line.split(":", 1)
                    parts[key.strip()] = base64.b64decode(val.strip())
            
            wrapped_key = parts.get('WRAP')
            nonce = parts.get('IV')
            tag = parts.get('TAG')
            ciphertext = parts.get('CTXT')

            if not all([wrapped_key, nonce, tag, ciphertext]):
                 raise ValueError("Missing components in the encrypted bundle.")

            # 2. Unwrap the Session Key (K_S) using Private Key
            session_key = unwrap_session_key(wrapped_key, self.private_key)
            self.log_activity("Session key unwrapped successfully.")

            # 3. Decrypt the Message (using K_S)
            plaintext = decrypt_message(session_key, nonce, ciphertext, tag)

            # 4. Display the Plaintext
            self.message_input_text.delete("1.0", tk.END)
            self.message_input_text.insert("1.0", plaintext)
            self.log_activity("SUCCESS: Decryption complete. Message displayed.")
            self.status_label.config(text="STATUS: DECRYPTION SUCCESS", fg="#00FF00")

        except Exception as e:
            messagebox.showerror("Decryption Failed", f"Decryption failed. Bundle may be corrupted or wrong key used: {e}")
            self.log_activity(f"DECRYPT FAILED: {e}")
            self.status_label.config(text="STATUS: FAILED", fg="red")
        """Placeholder for the primary decryption logic."""
        if not self.private_key:
            messagebox.showerror("Error", "Private Key not unlocked. Log in again.")
            self.log_activity("DECRYPT FAILED: Private Key unavailable.")
            return

        # Placeholder for actual crypto logic
        self.message_input_text.delete("1.0", tk.END)
        self.message_input_text.insert("1.0", "Hello, Alice. Decryption successful. This is plaintext.")
        self.log_activity("SUCCESS: Decryption complete. Message displayed.")
        self.status_label.config(text="STATUS: DECRYPTION SUCCESS", fg="#00FF00")

    def logout(self):
        """Wipes session state and returns to the login screen."""
        self.current_username = None
        self.master_key = None 
        self.private_key = None 
        self.public_key_pem = None 
        self.log_activity("Session wiped. Logging out.")
        self.show_login_screen()

# =========================================================================
# III. MAIN EXECUTION
# =========================================================================

if __name__ == '__main__':
    app = SecureApp()
    app.mainloop()