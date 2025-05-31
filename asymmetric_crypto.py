from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import logging
import traceback
from typing import Dict, Tuple, Optional, BinaryIO, Any, Union
import io

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AsymmetricCrypto:
    """
    Handles asymmetric cryptography operations for secure file sharing.
    Uses RSA for key exchange and digital signatures, and AES for file encryption.
    """
    
    @staticmethod
    def generate_key_pair(key_size: int = 2048) -> Tuple[str, str]:
        """
        Generate an RSA key pair.
        
        Args:
            key_size: Size of the RSA key in bits (2048 or 4096 recommended)
            
        Returns:
            Tuple of (public_key_pem, private_key_pem) as strings
        """
        try:
            # Generate a private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get the public key
            public_key = private_key.public_key()
            
            # Serialize the keys to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            logger.info(f"Generated RSA key pair with size {key_size} bits")
            return public_pem, private_pem
            
        except Exception as e:
            logger.error(f"Error generating RSA key pair: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to generate RSA key pair: {str(e)}")
    
    @staticmethod
    def load_public_key(public_key_pem: str):
        """
        Load a public key from PEM format with improved error handling.
        
        Args:
            public_key_pem: Public key in PEM format
            
        Returns:
            Public key object
        """
        try:
            logger.info(f"Attempting to load public key: {public_key_pem[:50]}...")
            
            # Clean up the PEM key - ensure it has proper formatting
            if "-----BEGIN PUBLIC KEY-----" not in public_key_pem:
                # Try to fix a key that might be missing headers/footers
                cleaned_key = "-----BEGIN PUBLIC KEY-----\n"
                cleaned_key += public_key_pem.strip()
                cleaned_key += "\n-----END PUBLIC KEY-----"
                public_key_pem = cleaned_key
                logger.info("Added missing PEM headers/footers to public key")
            
            # Ensure proper line breaks (PEM requires \n every 64 characters)
            lines = public_key_pem.split("\n")
            formatted_key = ""
            for line in lines:
                if "-----BEGIN" in line or "-----END" in line:
                    formatted_key += line + "\n"
                else:
                    # Process content lines, ensuring they're properly formatted
                    line = line.strip()
                    if line:
                        # Split long lines into 64-character chunks
                        chunks = [line[i:i+64] for i in range(0, len(line), 64)]
                        formatted_key += "\n".join(chunks) + "\n"
            
            logger.info(f"Formatted public key: {formatted_key[:100]}...")
            
            # Try to load the formatted key
            try:
                public_key = serialization.load_pem_public_key(
                    formatted_key.encode('utf-8'),
                    backend=default_backend()
                )
                logger.info("Successfully loaded formatted public key")
                return public_key
            except Exception as e:
                logger.warning(f"Failed to load formatted public key: {str(e)}, trying original key")
                # If that fails, try the original key
                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8'),
                    backend=default_backend()
                )
                logger.info("Successfully loaded original public key")
                return public_key
                
        except Exception as e:
            logger.error(f"Error loading public key: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to load public key: {str(e)}\n\nPlease ensure your key is in valid PEM format with proper BEGIN/END markers.")

    
    @staticmethod
    def load_private_key(private_key_pem: str):
        """
        Load a private key from PEM format with improved error handling.
        
        Args:
            private_key_pem: Private key in PEM format
            
        Returns:
            Private key object
        """
        try:
            logger.info(f"Attempting to load private key: {private_key_pem[:50]}...")
            
            # Clean up the PEM key - ensure it has proper formatting
            if "-----BEGIN PRIVATE KEY-----" not in private_key_pem and "-----BEGIN RSA PRIVATE KEY-----" not in private_key_pem:
                # Try to fix a key that might be missing headers/footers
                cleaned_key = "-----BEGIN PRIVATE KEY-----\n"
                cleaned_key += private_key_pem.strip()
                cleaned_key += "\n-----END PRIVATE KEY-----"
                private_key_pem = cleaned_key
                logger.info("Added missing PEM headers/footers to private key")
            
            # Ensure proper line breaks (PEM requires \n every 64 characters)
            lines = private_key_pem.split("\n")
            formatted_key = ""
            for line in lines:
                if "-----BEGIN" in line or "-----END" in line:
                    formatted_key += line + "\n"
                else:
                    # Process content lines, ensuring they're properly formatted
                    line = line.strip()
                    if line:
                        # Split long lines into 64-character chunks
                        chunks = [line[i:i+64] for i in range(0, len(line), 64)]
                        formatted_key += "\n".join(chunks) + "\n"
            
            logger.info(f"Formatted private key: {formatted_key[:100]}...")
            
            # Try to load the formatted key
            try:
                private_key = serialization.load_pem_private_key(
                    formatted_key.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                logger.info("Successfully loaded formatted private key")
                return private_key
            except Exception as e:
                logger.warning(f"Failed to load formatted private key: {str(e)}, trying original key")
                # If that fails, try the original key
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                logger.info("Successfully loaded original private key")
                return private_key
                
        except Exception as e:
            logger.error(f"Error loading private key: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to load private key: {str(e)}\n\nPlease ensure your key is in valid PEM format with proper BEGIN/END markers.")
    
    @staticmethod
    def encrypt_with_public_key(public_key, data: bytes) -> bytes:
        """
        Encrypt data using an RSA public key.
        
        Args:
            public_key: RSA public key object
            data: Data to encrypt (must be smaller than key size - padding)
            
        Returns:
            Encrypted data
        """
        try:
            logger.info(f"Encrypting data with public key, data size: {len(data)} bytes")
            encrypted = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.info(f"Data encrypted successfully, encrypted size: {len(encrypted)} bytes")
            return encrypted
        except Exception as e:
            logger.error(f"Error encrypting with public key: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to encrypt with public key: {str(e)}")
    
    @staticmethod
    def decrypt_with_private_key(private_key, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using an RSA private key.
        
        Args:
            private_key: RSA private key object
            encrypted_data: Data to decrypt
            
        Returns:
            Decrypted data
        """
        try:
            logger.info(f"Decrypting data with private key, encrypted data size: {len(encrypted_data)} bytes")
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.info(f"Data decrypted successfully, decrypted size: {len(decrypted)} bytes")
            return decrypted
        except Exception as e:
            logger.error(f"Error decrypting with private key: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to decrypt with private key: {str(e)}")
    
    @staticmethod
    def sign_data(private_key, data: bytes) -> bytes:
        """
        Create a digital signature for data using a private key.
        
        Args:
            private_key: RSA private key object
            data: Data to sign
            
        Returns:
            Digital signature
        """
        try:
            logger.info(f"Signing data with private key, data size: {len(data)} bytes")
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info(f"Data signed successfully, signature size: {len(signature)} bytes")
            return signature
        except Exception as e:
            logger.error(f"Error signing data: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to sign data: {str(e)}")
    
    @staticmethod
    def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
        """
        Verify a digital signature using a public key.
        
        Args:
            public_key: RSA public key object
            data: Original data that was signed
            signature: Digital signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            logger.info(f"Verifying signature with public key, data size: {len(data)} bytes, signature size: {len(signature)} bytes")
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("Signature verified successfully")
            return True
        except Exception as e:
            logger.warning(f"Signature verification failed: {str(e)}")
            return False
    
    @staticmethod
    def generate_aes_key(key_size: int = 32) -> bytes:
        """
        Generate a random AES key.
        
        Args:
            key_size: Size of the key in bytes (32 for AES-256)
            
        Returns:
            Random AES key
        """
        logger.info(f"Generating random AES key of size {key_size} bytes")
        return os.urandom(key_size)
    
    @staticmethod
    def encrypt_file_with_aes_gcm(file_data: bytes, aes_key: bytes) -> Dict[str, bytes]:
        """
        Encrypt file data using AES-GCM.
        
        Args:
            file_data: File data to encrypt
            aes_key: AES key
            
        Returns:
            Dictionary containing encrypted data, nonce, and tag
        """
        try:
            logger.info(f"Encrypting file with AES-GCM, file size: {len(file_data)} bytes")
            # Generate a random 96-bit IV (recommended for GCM)
            nonce = os.urandom(12)
            
            # Create an encryptor object
            encryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()
            
            # Encrypt the data
            ciphertext = encryptor.update(file_data) + encryptor.finalize()
            
            logger.info(f"File encrypted successfully, encrypted size: {len(ciphertext)} bytes")
            
            # Return the encrypted data, nonce, and tag
            return {
                'ciphertext': ciphertext,
                'nonce': nonce,
                'tag': encryptor.tag
            }
        except Exception as e:
            logger.error(f"Error encrypting file with AES-GCM: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to encrypt file with AES-GCM: {str(e)}")
    
    @staticmethod
    def decrypt_file_with_aes_gcm(encrypted_data: Dict[str, bytes], aes_key: bytes) -> bytes:
        """
        Decrypt file data using AES-GCM.
        
        Args:
            encrypted_data: Dictionary containing encrypted data, nonce, and tag
            aes_key: AES key
            
        Returns:
            Decrypted file data
        """
        try:
            # Extract the ciphertext, nonce, and tag
            ciphertext = encrypted_data['ciphertext']
            nonce = encrypted_data['nonce']
            tag = encrypted_data['tag']
            
            logger.info(f"Decrypting file with AES-GCM, encrypted size: {len(ciphertext)} bytes")
            
            # Create a decryptor object
            decryptor = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            
            # Decrypt the data
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            logger.info(f"File decrypted successfully, decrypted size: {len(plaintext)} bytes")
            
            return plaintext
        except Exception as e:
            logger.error(f"Error decrypting file with AES-GCM: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to decrypt file with AES-GCM: {str(e)}")
    
    @classmethod
    def encrypt_file_for_recipient(cls, 
                                  file_data: bytes, 
                                  recipient_public_key_pem: str, 
                                  sender_private_key_pem: Optional[str] = None) -> Dict[str, str]:
        """
        Encrypt a file for a recipient using their public key.
        
        Args:
            file_data: File data to encrypt
            recipient_public_key_pem: Recipient's public key in PEM format
            sender_private_key_pem: Sender's private key in PEM format (for signing)
            
        Returns:
            Dictionary containing all necessary data for the recipient to decrypt the file
        """
        try:
            logger.info(f"Encrypting file for recipient, file size: {len(file_data)} bytes")
            
            # Load the recipient's public key
            recipient_public_key = cls.load_public_key(recipient_public_key_pem)
            
            # Generate a random AES key
            aes_key = cls.generate_aes_key()
            
            # Encrypt the file with AES-GCM
            encrypted_file = cls.encrypt_file_with_aes_gcm(file_data, aes_key)
            
            # Encrypt the AES key with the recipient's public key
            encrypted_aes_key = cls.encrypt_with_public_key(recipient_public_key, aes_key)
            
            # Prepare the result
            result = {
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'encrypted_file': base64.b64encode(encrypted_file['ciphertext']).decode('utf-8'),
                'nonce': base64.b64encode(encrypted_file['nonce']).decode('utf-8'),
                'tag': base64.b64encode(encrypted_file['tag']).decode('utf-8'),
            }
            
            # Add a digital signature if a sender private key is provided
            if sender_private_key_pem:
                logger.info("Adding digital signature to encrypted file")
                sender_private_key = cls.load_private_key(sender_private_key_pem)
                
                # Create a signature of the encrypted file
                data_to_sign = encrypted_file['ciphertext'] + encrypted_file['nonce'] + encrypted_file['tag']
                signature = cls.sign_data(sender_private_key, data_to_sign)
                
                result['signature'] = base64.b64encode(signature).decode('utf-8')
                result['is_signed'] = True
            else:
                result['is_signed'] = False
            
            logger.info("File encrypted successfully for recipient")
            return result
            
        except Exception as e:
            logger.error(f"Error encrypting file for recipient: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to encrypt file for recipient: {str(e)}")
    
    @classmethod
    def decrypt_file_from_sender(cls,
                                encrypted_data: Dict[str, str],
                                recipient_private_key_pem: str,
                                sender_public_key_pem: Optional[str] = None) -> Dict[str, Any]:
        """
        Decrypt a file that was encrypted for the recipient.
        
        Args:
            encrypted_data: Dictionary containing the encrypted file data
            recipient_private_key_pem: Recipient's private key in PEM format
            sender_public_key_pem: Sender's public key in PEM format (for signature verification)
            
        Returns:
            Dictionary containing the decrypted file and verification status
        """
        try:
            logger.info("Decrypting file from sender")
            logger.info(f"Encrypted data keys: {list(encrypted_data.keys())}")
            
            # Validate required fields
            required_fields = ['encrypted_aes_key', 'encrypted_file', 'nonce', 'tag']
            for field in required_fields:
                if field not in encrypted_data:
                    raise ValueError(f"Missing required field in encrypted data: {field}")
            
            # Load the recipient's private key
            recipient_private_key = cls.load_private_key(recipient_private_key_pem)
            
            # Decode the encrypted data
            try:
                encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_aes_key'])
                encrypted_file = base64.b64decode(encrypted_data['encrypted_file'])
                nonce = base64.b64decode(encrypted_data['nonce'])
                tag = base64.b64decode(encrypted_data['tag'])
                
                logger.info(f"Decoded encrypted data: key={len(encrypted_aes_key)} bytes, file={len(encrypted_file)} bytes, nonce={len(nonce)} bytes, tag={len(tag)} bytes")
            except Exception as e:
                logger.error(f"Error decoding base64 data: {str(e)}\n{traceback.format_exc()}")
                raise ValueError(f"Failed to decode encrypted data: {str(e)}")
            
            # Decrypt the AES key with the recipient's private key
            try:
                aes_key = cls.decrypt_with_private_key(recipient_private_key, encrypted_aes_key)
                logger.info(f"AES key decrypted successfully, key size: {len(aes_key)} bytes")
            except Exception as e:
                logger.error(f"Error decrypting AES key: {str(e)}\n{traceback.format_exc()}")
                raise ValueError(f"Failed to decrypt AES key: {str(e)}")
            
            # Verify the signature if provided and if sender's public key is available
            signature_verified = False
            if encrypted_data.get('is_signed', False) and sender_public_key_pem:
                logger.info("Verifying digital signature")
                try:
                    sender_public_key = cls.load_public_key(sender_public_key_pem)
                    signature = base64.b64decode(encrypted_data['signature'])
                    data_to_verify = encrypted_file + nonce + tag
                    signature_verified = cls.verify_signature(sender_public_key, data_to_verify, signature)
                    
                    if not signature_verified:
                        logger.warning("Signature verification failed")
                except Exception as e:
                    logger.error(f"Error during signature verification: {str(e)}\n{traceback.format_exc()}")
                    # Continue with decryption even if signature verification fails
            
            # Decrypt the file with the AES key
            try:
                decrypted_file = cls.decrypt_file_with_aes_gcm({
                    'ciphertext': encrypted_file,
                    'nonce': nonce,
                    'tag': tag
                }, aes_key)
                logger.info(f"File decrypted successfully, size: {len(decrypted_file)} bytes")
            except Exception as e:
                logger.error(f"Error decrypting file with AES key: {str(e)}\n{traceback.format_exc()}")
                raise ValueError(f"Failed to decrypt file with AES key: {str(e)}")
            
            return {
                'decrypted_file': decrypted_file,
                'signature_verified': signature_verified if encrypted_data.get('is_signed', False) else None
            }
            
        except Exception as e:
            logger.error(f"Error decrypting file from sender: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Failed to decrypt file from sender: {str(e)}")
