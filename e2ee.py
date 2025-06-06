
import os
import base64
import json
import time
import secrets
import hashlib
import getpass
from typing import Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from hashlib import blake2b

@dataclass
class E2EEConfig:
    nonce_cache_file: str = "used_nonces.json"
    trusted_keys_file: str = "trusted_keys.json"
    security_log_file: str = "security_events.log"
    replay_window_seconds: int = 120
    key_backup_dir: str = "key_backups"
    key_derivation_info: bytes = b'e2ee-handshake-v3'
    salt_size: int = 32
    max_message_size: int = 1024 * 1024  
    pbkdf2_iterations: int = 100000
    version: int = 62420113282009

CONFIG = E2EEConfig()

class SecurityLogger:
    @staticmethod
    def log_event(event_type: str, details: str, severity: str = "INFO"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        log_entry = f"[{timestamp}] {severity}: {event_type} - {details}\n"
        
        try:
            with open(CONFIG.security_log_file, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Failed to write security log: {e}")
        
        if severity in ["ERROR", "CRITICAL"]:
            print(f"SECURITY {severity}: {details}")

class SecureStorage:
    def __init__(self, password: str):
        self.password = password
        self._derive_key()
    
    def _derive_key(self):
        salt = b"e2ee_storage_salt_v1"  
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CONFIG.pbkdf2_iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        self.fernet = Fernet(key)
    
    def encrypt_data(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def save_encrypted_file(self, filename: str, data: Dict[str, Any]):
        try:
            json_data = json.dumps(data)
            encrypted = self.encrypt_data(json_data)
            with open(filename, "w") as f:
                f.write(encrypted)
            SecurityLogger.log_event("FILE_SAVE", f"Encrypted data saved to {filename}")
        except Exception as e:
            SecurityLogger.log_event("FILE_SAVE_ERROR", f"Failed to save {filename}: {e}", "ERROR")
            raise
    
    def load_encrypted_file(self, filename: str) -> Dict[str, Any]:
        try:
            if not os.path.exists(filename):
                return {}
            
            with open(filename, "r") as f:
                encrypted = f.read()
            
            decrypted = self.decrypt_data(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            SecurityLogger.log_event("FILE_LOAD_ERROR", f"Failed to load {filename}: {e}", "ERROR")
            return {}


class InputValidator:
    @staticmethod
    def validate_base64(data: str, expected_length: Optional[int] = None) -> bytes:
        try:
            decoded = base64.b64decode(data)
            if expected_length and len(decoded) != expected_length:
                raise ValueError(f"Invalid length: expected {expected_length}, got {len(decoded)}")
            return decoded
        except Exception as e:
            raise ValueError(f"Invalid base64 data: {e}")
    
    @staticmethod
    def validate_message(message: str):
        if not message:
            raise ValueError("Message cannot be empty")
        if len(message.encode()) > CONFIG.max_message_size:
            raise ValueError(f"Message too large (max {CONFIG.max_message_size} bytes)")
    
    @staticmethod
    def validate_timestamp(timestamp: int, window_seconds: int = CONFIG.replay_window_seconds):
        now = int(time.time())
        if abs(now - timestamp) > window_seconds:
            raise ValueError("Message timestamp outside allowable window")

class NonceManager:
    def __init__(self, storage: SecureStorage):
        self.storage = storage
        self.cache_file = CONFIG.nonce_cache_file
    
    def load_nonce_cache(self) -> Dict[str, int]:
        return self.storage.load_encrypted_file(self.cache_file)
    
    def save_nonce_cache(self, cache: Dict[str, int]):
        self.storage.save_encrypted_file(self.cache_file, cache)
    
    def is_nonce_used(self, nonce_b64: str) -> bool:
        cache = self.load_nonce_cache()
        return nonce_b64 in cache
    
    def register_nonce(self, nonce_b64: str):
        cache = self.load_nonce_cache()
        cache[nonce_b64] = int(time.time())
    
        cutoff = int(time.time()) - CONFIG.replay_window_seconds
        cache = {k: v for k, v in cache.items() if v > cutoff}
        
        self.save_nonce_cache(cache)
        SecurityLogger.log_event("NONCE_REGISTERED", f"Nonce registered: {nonce_b64[:16]}...")


@dataclass
class TrustedKey:
    key_id: str
    public_key: str
    first_seen: int
    pin_data: Optional[str] = None
    trusted: bool = True

class TrustedKeyManager:
    def __init__(self, storage: SecureStorage):
        self.storage = storage
        self.keys_file = CONFIG.trusted_keys_file
    
    def load_trusted_keys(self) -> Dict[str, TrustedKey]:
        """Load trusted keys"""
        data = self.storage.load_encrypted_file(self.keys_file)
        return {k: TrustedKey(**v) for k, v in data.items()}
    
    def save_trusted_keys(self, keys: Dict[str, TrustedKey]):
        """Save trusted keys"""
        data = {k: asdict(v) for k, v in keys.items()}
        self.storage.save_encrypted_file(self.keys_file, data)
    
    def trust_key(self, verify_key_b64: str, pin_data: Optional[str] = None):
        """Trust a verification key"""
        keys = self.load_trusted_keys()
        
        if verify_key_b64 in keys:
            SecurityLogger.log_event("KEY_ALREADY_TRUSTED", f"Key already trusted: {verify_key_b64[:16]}...")
            return
        
        trusted_key = TrustedKey(
            key_id=verify_key_b64,
            public_key=verify_key_b64,
            first_seen=int(time.time()),
            pin_data=pin_data,
            trusted=True
        )
        
        keys[verify_key_b64] = trusted_key
        self.save_trusted_keys(keys)
        SecurityLogger.log_event("KEY_TRUSTED", f"Key trusted: {verify_key_b64[:16]}...")
    
    def is_trusted_key(self, verify_key_b64: str) -> bool:
        """Check if key is trusted"""
        keys = self.load_trusted_keys()
        return verify_key_b64 in keys and keys[verify_key_b64].trusted


class KeyManager:
    def __init__(self, storage: SecureStorage):
        self.storage = storage
        self.backup_dir = CONFIG.key_backup_dir
        
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def backup_keys(self, key_type: str, key_data: Dict[str, Any]):
        """Backup keys before rotation"""
        timestamp = int(time.time())
        backup_file = os.path.join(self.backup_dir, f"{key_type}_{timestamp}.json")
        
        try:
            with open(backup_file, "w") as f:
                json.dump(key_data, f)
            SecurityLogger.log_event("KEY_BACKUP", f"Keys backed up: {backup_file}")
        except Exception as e:
            SecurityLogger.log_event("KEY_BACKUP_ERROR", f"Backup failed: {e}", "ERROR")
    
    def generate_identity_keys(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        signing_key = ed25519.Ed25519PrivateKey.generate()
        verify_key = signing_key.public_key()
        

        old_data = self.storage.load_encrypted_file("identity_keys.enc")
        if old_data:
            self.backup_keys("identity", old_data)
        
        key_data = {
            "signing_key": base64.b64encode(signing_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode(),
            "verify_key": base64.b64encode(verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
            "created": int(time.time())
        }
        
        self.storage.save_encrypted_file("identity_keys.enc", key_data)
        SecurityLogger.log_event("IDENTITY_KEYS_GENERATED", "New identity keys generated")
        
        return signing_key, verify_key
    
    def load_identity_keys(self) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        key_data = self.storage.load_encrypted_file("identity_keys.enc")
        
        if not key_data:
            return self.generate_identity_keys()
        
        try:
            signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(key_data["signing_key"])
            )
            verify_key = ed25519.Ed25519PublicKey.from_public_bytes(
                base64.b64decode(key_data["verify_key"])
            )
            return signing_key, verify_key
        except Exception as e:
            SecurityLogger.log_event("KEY_LOAD_ERROR", f"Failed to load identity keys: {e}", "ERROR")
            return self.generate_identity_keys()
    
    def generate_recipient_key(self) -> x25519.X25519PrivateKey:
        private_key = x25519.X25519PrivateKey.generate()
        
        old_data = self.storage.load_encrypted_file("recipient_key.enc")
        if old_data:
            self.backup_keys("recipient", old_data)
            
        key_data = {
            "private_key": base64.b64encode(private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode(),
            "public_key": base64.b64encode(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
            "created": int(time.time())
        }
        
        self.storage.save_encrypted_file("recipient_key.enc", key_data)
        SecurityLogger.log_event("RECIPIENT_KEY_GENERATED", "New recipient key generated")
        
        return private_key
    
    def load_recipient_key(self) -> x25519.X25519PrivateKey:
        """Load or generate recipient key"""
        key_data = self.storage.load_encrypted_file("recipient_key.enc")
        
        if not key_data:
            return self.generate_recipient_key()
        
        try:
            private_key = x25519.X25519PrivateKey.from_private_bytes(
                base64.b64decode(key_data["private_key"])
            )
            return private_key
        except Exception as e:
            SecurityLogger.log_event("KEY_LOAD_ERROR", f"Failed to load recipient key: {e}", "ERROR")
            return self.generate_recipient_key()

class CryptoEngine:
    @staticmethod
    def derive_shared_key(ephemeral_private: x25519.X25519PrivateKey, recipient_pub_bytes: bytes) -> bytes:
        try:
            recipient_pub = x25519.X25519PublicKey.from_public_bytes(recipient_pub_bytes)
            shared_secret = ephemeral_private.exchange(recipient_pub)
            
            
            salt = blake2b(shared_secret, digest_size=CONFIG.salt_size).digest()
            
            
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                info=CONFIG.key_derivation_info
            )
            
            return hkdf.derive(shared_secret)
        except Exception as e:
            SecurityLogger.log_event("KEY_DERIVATION_ERROR", f"Failed to derive the shared key: {e}", "ERROR")
            raise
    
    @staticmethod
    def encrypt_message(
        message: str, 
        recipient_pub_b64: str, 
        identity_signing_key: ed25519.Ed25519PrivateKey
    ) -> Dict[str, str]:
        
        
        InputValidator.validate_message(message)
        recipient_pub_bytes = InputValidator.validate_base64(recipient_pub_b64, 32)
        
        try:
            
            ephemeral_private = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            
            
            shared_key = CryptoEngine.derive_shared_key(ephemeral_private, recipient_pub_bytes)
            
            
            nonce = secrets.token_bytes(12)
            nonce_b64 = base64.b64encode(nonce).decode()
            
            
            aead = ChaCha20Poly1305(shared_key)
            
            
            sender_verify_key_bytes = identity_signing_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            sender_b64 = base64.b64encode(sender_verify_key_bytes).decode()
            timestamp = int(time.time())
            
            metadata = {
                "timestamp": timestamp,
                "sender": sender_b64,
                "nonce_hash": blake2b(nonce, digest_size=16).hexdigest(),
                "version": CONFIG.version
            }
            metadata_bytes = json.dumps(metadata, separators=(',', ':')).encode()
            
            
            ciphertext = aead.encrypt(nonce, message.encode('utf-8'), metadata_bytes)
            
            
            ephemeral_pub_bytes = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            signature_data = ephemeral_pub_bytes + nonce + ciphertext + metadata_bytes
            signature = identity_signing_key.sign(signature_data)
            
            result = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": nonce_b64,
                "ephemeral_pub": base64.b64encode(ephemeral_pub_bytes).decode(),
                "signature": base64.b64encode(signature).decode(),
                "metadata": base64.b64encode(metadata_bytes).decode(),
                "version": str(CONFIG.version)
            }
            
            SecurityLogger.log_event("MESSAGE_ENCRYPTED", f"Message encrypted for {recipient_pub_b64[:16]}...")
            return result
            
        except Exception as e:
            SecurityLogger.log_event("ENCRYPTION_ERROR", f"Encryption failed: {e}", "ERROR")
            raise
    
    @staticmethod
    def decrypt_message(
        data: Dict[str, str], 
        recipient_private_key: x25519.X25519PrivateKey,
        trusted_keys: TrustedKeyManager,
        nonce_manager: NonceManager
    ) -> str:
        
        try:
            
            ciphertext = base64.b64decode(data["ciphertext"])
            nonce = base64.b64decode(data["nonce"])
            nonce_b64 = data["nonce"]
            ephemeral_pub_bytes = InputValidator.validate_base64(data["ephemeral_pub"], 32)
            signature = base64.b64decode(data["signature"])
            metadata_bytes = base64.b64decode(data["metadata"])
            
            
            metadata = json.loads(metadata_bytes.decode())
            sender_b64 = metadata["sender"]
            
            
            msg_version = metadata.get("version", 1)
            if msg_version < 2:
                raise ValueError("Unsupported message version")
            
            
            if not trusted_keys.is_trusted_key(sender_b64):
                raise ValueError("Can't trust the sender key")
            
            
            if nonce_manager.is_nonce_used(nonce_b64):
                raise ValueError("Replay detected: nonce already used")
            
            
            InputValidator.validate_timestamp(metadata["timestamp"])
            
            
            sender_verify_key_bytes = InputValidator.validate_base64(sender_b64, 32)
            sender_verify_key = ed25519.Ed25519PublicKey.from_public_bytes(sender_verify_key_bytes)
            
            signature_data = ephemeral_pub_bytes + nonce + ciphertext + metadata_bytes
            
            try:
                sender_verify_key.verify(signature, signature_data)
            except InvalidSignature:
                raise ValueError("Invalid - message authenticity can't be verified")
            
            shared_key = CryptoEngine.derive_shared_key(recipient_private_key, ephemeral_pub_bytes)
            aead = ChaCha20Poly1305(shared_key)
            plaintext = aead.decrypt(nonce, ciphertext, metadata_bytes)
            nonce_manager.register_nonce(nonce_b64)
            message = plaintext.decode('utf-8')
            SecurityLogger.log_event("MESSAGE_DECRYPTED", f"Message decrypted from {sender_b64[:16]}...")
            return message
            
        except Exception as e:
            SecurityLogger.log_event("DECRYPTION_ERROR", f"Decryption failed: {e}", "ERROR")
            raise

class E2EEMessenger:
    def __init__(self):
        self.storage = None
        self.key_manager = None
        self.trusted_keys = None
        self.nonce_manager = None
        self.signing_key = None
        self.verify_key = None
        self.recipient_private = None
        self.recipient_public = None
    
    def initialize(self, password: str):
        try:
            self.storage = SecureStorage(password)
            self.key_manager = KeyManager(self.storage)
            self.trusted_keys = TrustedKeyManager(self.storage)
            self.nonce_manager = NonceManager(self.storage)
            
            
            self.signing_key, self.verify_key = self.key_manager.load_identity_keys()
            self.recipient_private = self.key_manager.load_recipient_key()
            self.recipient_public = self.recipient_private.public_key()
            
            
            verify_key_b64 = base64.b64encode(self.verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode()
            self.trusted_keys.trust_key(verify_key_b64)
            
            SecurityLogger.log_event("SYSTEM_INITIALIZED", "E2EE system initialized successfully")
            
        except Exception as e:
            SecurityLogger.log_event("INIT_ERROR", f"System initialization failed: {e}", "CRITICAL")
            raise
    
    def get_public_keys(self) -> Dict[str, str]:
        """Get public keys for sharing"""
        verify_key_b64 = base64.b64encode(self.verify_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode()
        
        recipient_key_b64 = base64.b64encode(self.recipient_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )).decode()
        
        return {
            "verify_key": verify_key_b64,
            "recipient_key": recipient_key_b64
        }
    
    def encrypt_message(self, message: str, recipient_pub_b64: str) -> Dict[str, str]:
        """Encrypt a message"""
        return CryptoEngine.encrypt_message(message, recipient_pub_b64, self.signing_key)
    
    def decrypt_message(self, data: Dict[str, str]) -> str:
        """Decrypt a message"""
        return CryptoEngine.decrypt_message(
            data, self.recipient_private, self.trusted_keys, self.nonce_manager
        )
    
    def trust_key(self, verify_key_b64: str, pin_data: Optional[str] = None):
        """Trust a verification key"""
        self.trusted_keys.trust_key(verify_key_b64, pin_data)
    
    def rotate_keys(self, key_type: str):
        """Rotate cryptographic keys"""
        if key_type in ["identity", "both"]:
            self.signing_key, self.verify_key = self.key_manager.generate_identity_keys()
            
            verify_key_b64 = base64.b64encode(self.verify_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode()
            self.trusted_keys.trust_key(verify_key_b64)
        
        if key_type in ["recipient", "both"]:
            self.recipient_private = self.key_manager.generate_recipient_key()
            self.recipient_public = self.recipient_private.public_key()


def get_secure_password() -> str:
    """Get password securely from user"""
    while True:
        password = getpass.getpass("Enter master password (min 12 chars): ")
        if len(password) < 12:
            print("Password must be at least 12 characters long")
            continue
        
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match")
            continue
        
        return password

def display_help():
    """Display help menu"""
    print("""
  e - Encrypt a message
  d - Decrypt a message  
  r - Rotate keys (identity/recipient/both)
  t - Trust a verification key
  k - Show your public keys
  l - (last 10 events)
  h - (show this menu)
  q - Quit the program
""")

def main():
    print("=" * 50)
    
    password = get_secure_password()
    messenger = E2EEMessenger()
    
    try:
        messenger.initialize(password)
        print("System initialized successfully!")
    except Exception as e:
        print(f"Initialization failed: {e}")
        return
    
    
    keys = messenger.get_public_keys()
    print(f" Your Public Keys:")
    print(f"Verify Key (share for trust): {keys['verify_key']}")
    print(f"Recipient Key (share to receive): {keys['recipient_key']}")
    
    display_help()
    
    while True:
        try:
            action = input("\n> ").strip().lower()
            
            if action == 'e':
                message = input("Message to encrypt: ")
                recipient_key = input("Recipient public key (base64): ").strip()
                
                encrypted = messenger.encrypt_message(message, recipient_key)
                print("Encrypted Message Data:")
                for key, value in encrypted.items():
                    print(f"{key}: {value}")
                
            elif action == 'd':
                print("Enter encrypted message components:")
                fields = {}
                for field in ['ciphertext', 'nonce', 'ephemeral_pub', 'signature', 'metadata', 'version']:
                    fields[field] = input(f"{field}: ").strip()
                
                decrypted = messenger.decrypt_message(fields)
                print(f"Decrypted: {decrypted}")
                
            elif action == 'r':
                key_type = input("Rotate (i)dentity, (r)ecipient, or (b)oth? ").strip().lower()
                type_map = {'i': 'identity', 'r': 'recipient', 'b': 'both'}
                
                if key_type in type_map:
                    messenger.rotate_keys(type_map[key_type])
                    print(f"{type_map[key_type].title()} keys rotated")
                    
                    if key_type in ['i', 'b']:
                        keys = messenger.get_public_keys()
                        print(f"New verify key: {keys['verify_key']}")
                    if key_type in ['r', 'b']:
                        keys = messenger.get_public_keys()
                        print(f"New recipient key: {keys['recipient_key']}")
                else:
                    print("Invalid option")
                    
            elif action == 't':
                key_to_trust = input("Verification key to trust (base64): ").strip()
                pin_data = input("Optional PIN data (press enter to skip): ").strip() or None
                
                messenger.trust_key(key_to_trust, pin_data)
                print("Key trusted")
                
            elif action == 'k':
                keys = messenger.get_public_keys()
                print(f"\n🔑 Your Public Keys:")
                print(f"Verify Key: {keys['verify_key']}")
                print(f"Recipient Key: {keys['recipient_key']}")
                
            elif action == 'l':
                if os.path.exists(CONFIG.security_log_file):
                    with open(CONFIG.security_log_file, 'r') as f:
                        lines = f.readlines()
                    print("\n📋 Recent Security Events:")
                    for line in lines[-10:]:
                        print(line.strip())
                else:
                    print("No security log found")
                    
            elif action == 'h':
                display_help()
                
            elif action == 'q':
                print("Goodbye!")
                break
                
            else:
                print("Unknown command. Type 'h' for help.")
                
        except KeyboardInterrupt:
            print("Goodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
