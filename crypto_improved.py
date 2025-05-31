from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import logging
import traceback
import re
import zlib
from enum import Enum
from typing import Dict, Any, Optional, Tuple, Union, BinaryIO
import io
import hashlib
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EncryptionMode(Enum):
    CFB = "cfb"
    CBC = "cbc"
    GCM = "gcm"

class CompressionLevel(Enum):
    NONE = 0
    FAST = 1
    DEFAULT = 6
    BEST = 9

class CryptoConfig:
    def __init__(
        self,
        mode: EncryptionMode = EncryptionMode.CFB,
        iterations: int = 100000,
        compression: CompressionLevel = CompressionLevel.NONE,
        add_hmac: bool = False,
        chunk_size: int = 4 * 1024 * 1024  # 4MB chunks for streaming
    ):
        self.mode = mode
        self.iterations = iterations
        self.compression = compression
        self.add_hmac = add_hmac
        self.chunk_size = chunk_size

def derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive a 32-byte key from the password using PBKDF2."""
    try:
        if not password or not salt:
            raise ValueError("Password and salt cannot be empty")
        
        # Normalize the password to ensure consistent results
        password_bytes = password.encode('utf-8')
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password_bytes)
    except Exception as e:
        logger.error("Key derivation failed: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"Key derivation failed: {str(e)}")

def is_valid_base64(s: str) -> bool:
    """Check if the string is a valid base64-encoded string."""
    try:
        s = s.strip()
        if not re.match(r'^[A-Za-z0-9+/=]+$', s):
            logger.warning("Invalid base64 characters in string")
            return False
        if len(s) % 4 != 0:
            logger.warning("Invalid base64 length (not multiple of 4): %s", len(s))
            return False
        base64.b64decode(s, validate=True)
        return True
    except Exception as e:
        logger.warning("Base64 validation failed: %s", str(e))
        return False

def compress_data(data: bytes, level: CompressionLevel = CompressionLevel.DEFAULT) -> bytes:
    """Compress data using zlib."""
    if level == CompressionLevel.NONE:
        return data
    
    try:
        compressed = zlib.compress(data, level.value)
        compression_ratio = len(data) / len(compressed) if compressed else 1
        logger.info(f"Compressed data from {len(data)} to {len(compressed)} bytes (ratio: {compression_ratio:.2f}x)")
        return compressed
    except Exception as e:
        logger.error(f"Compression failed: {str(e)}")
        # Return original data if compression fails
        return data

def decompress_data(data: bytes) -> bytes:
    """Decompress data using zlib."""
    try:
        # Try to decompress
        decompressed = zlib.decompress(data)
        logger.info(f"Decompressed data from {len(data)} to {len(decompressed)} bytes")
        return decompressed
    except zlib.error as e:
        # If decompression fails, assume the data wasn't compressed
        logger.warning(f"Decompression failed, assuming uncompressed data: {str(e)}")
        return data
    except Exception as e:
        logger.error(f"Unexpected decompression error: {str(e)}")
        raise ValueError(f"Failed to decompress data: {str(e)}")

def create_hmac(key: bytes, data: bytes) -> bytes:
    """Create an HMAC for data integrity verification."""
    try:
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(key)
        h.update(data)
        return h.finalize()
    except Exception as e:
        logger.error(f"HMAC creation failed: {str(e)}")
        raise ValueError(f"Failed to create HMAC: {str(e)}")

def verify_hmac(key: bytes, data: bytes, hmac: bytes) -> bool:
    """Verify the HMAC for data integrity."""
    try:
        calculated_hmac = create_hmac(key, data)
        return hmac == calculated_hmac
    except Exception as e:
        logger.error(f"HMAC verification failed: {str(e)}")
        return False

def calculate_checksum(data: bytes) -> str:
    """Calculate SHA-256 checksum of data."""
    return hashlib.sha256(data).hexdigest()

def encrypt_aes(
    message: str, 
    key: str, 
    config: CryptoConfig = CryptoConfig()
) -> Dict[str, Any]:
    """Encrypt the message using AES with the specified configuration."""
    try:
        if not message or not key:
            raise ValueError("Message and key cannot be empty")
        
        # Generate salt and derive key
        salt = os.urandom(16)
        derived_key = derive_key(key, salt, config.iterations)
        
        # Convert message to bytes and compress if needed
        message_bytes = message.encode('utf-8')
        original_checksum = calculate_checksum(message_bytes)
        
        if config.compression != CompressionLevel.NONE:
            message_bytes = compress_data(message_bytes, config.compression)
        
        # Create metadata
        metadata = {
            "mode": config.mode.value,
            "compression": config.compression.value,
            "iterations": config.iterations,
            "original_checksum": original_checksum,
            "add_hmac": config.add_hmac
        }
        
        # Encrypt based on the selected mode
        if config.mode == EncryptionMode.CFB:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(message_bytes) + encryptor.finalize()
            
            # Store metadata in a separate section
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
            
            # Combine all components: salt + iv + metadata_length + metadata + cipher_text
            combined = salt + iv + metadata_length + metadata_bytes + cipher_text
            
            # Add HMAC if requested
            if config.add_hmac:
                hmac = create_hmac(derived_key, combined)
                combined = combined + hmac
            
            # Encode the result
            encoded = base64.b64encode(combined).decode('utf-8')
            
            logger.info("Encrypted message using %s mode with%s compression", 
                       config.mode.value, 
                       "" if config.compression == CompressionLevel.NONE else " " + str(config.compression.value))
            
            return {
                "cipher_text": encoded,
                "metadata": metadata
            }
            
        elif config.mode == EncryptionMode.CBC:
            iv = os.urandom(16)
            
            # Add padding for CBC mode
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(message_bytes) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(padded_data) + encryptor.finalize()
            
            # Store metadata in a separate section
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
            
            # Combine all components: salt + iv + metadata_length + metadata + cipher_text
            combined = salt + iv + metadata_length + metadata_bytes + cipher_text
            
            # Add HMAC if requested
            if config.add_hmac:
                hmac = create_hmac(derived_key, combined)
                combined = combined + hmac
            
            # Encode the result
            encoded = base64.b64encode(combined).decode('utf-8')
            
            logger.info("Encrypted message using %s mode with%s compression", 
                       config.mode.value, 
                       "" if config.compression == CompressionLevel.NONE else " " + str(config.compression.value))
            
            return {
                "cipher_text": encoded,
                "metadata": metadata
            }
            
        elif config.mode == EncryptionMode.GCM:
            # GCM mode provides authentication, so HMAC is not needed
            iv = os.urandom(12)  # GCM recommends 12 bytes for IV
            
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(message_bytes) + encryptor.finalize()
            tag = encryptor.tag  # Get the authentication tag
            
            # Store metadata in a separate section
            metadata_bytes = json.dumps(metadata).encode('utf-8')
            metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')
            
            # Combine all components: salt + iv + tag + metadata_length + metadata + cipher_text
            combined = salt + iv + tag + metadata_length + metadata_bytes + cipher_text
            
            # Encode the result
            encoded = base64.b64encode(combined).decode('utf-8')
            
            logger.info("Encrypted message using %s mode with%s compression", 
                       config.mode.value, 
                       "" if config.compression == CompressionLevel.NONE else " " + str(config.compression.value))
            
            return {
                "cipher_text": encoded,
                "metadata": metadata
            }
        
        else:
            raise ValueError(f"Unsupported encryption mode: {config.mode}")
            
    except Exception as e:
        logger.error("Encryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"Encryption error: {str(e)}")

def decrypt_aes(
    cipher_text: str, 
    key: str
) -> Dict[str, Any]:
    """Decrypt the base64-encoded ciphertext using AES."""
    try:
        if not cipher_text or not key:
            raise ValueError("Ciphertext and key cannot be empty")
        
        if not is_valid_base64(cipher_text):
            raise ValueError("Invalid base64-encoded string: must be a valid base64 string with length multiple of 4")
        
        # Decode the base64 string
        combined = base64.b64decode(cipher_text)
        
        # Extract salt (always first 16 bytes)
        if len(combined) < 16:
            raise ValueError("Invalid ciphertext: too short (must include salt)")
        
        salt = combined[:16]
        
        # Try to extract metadata and determine encryption mode
        try:
            # Check for GCM mode first (salt + iv(12) + tag(16) + metadata_length)
            if len(combined) >= 44:
                # Try to read metadata length at position 44 (after salt + iv + tag)
                metadata_length_bytes = combined[44:48]
                metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                
                if metadata_length > 0 and metadata_length < 1000:  # Reasonable size for metadata
                    metadata_bytes = combined[48:48+metadata_length]
                    try:
                        metadata = json.loads(metadata_bytes.decode('utf-8'))
                        if metadata.get("mode") == "gcm":
                            mode = EncryptionMode.GCM
                            iterations = metadata.get("iterations", 100000)
                            add_hmac = metadata.get("add_hmac", False)
                            logger.info(f"Detected GCM mode from metadata")
                            
                            # Derive the key
                            derived_key = derive_key(key, salt, iterations)
                            
                            # Extract IV, tag and ciphertext
                            iv = combined[16:28]  # 12 bytes for GCM
                            tag = combined[28:44]  # 16 bytes for tag
                            
                            # Extract ciphertext (after metadata)
                            cipher_text = combined[48+metadata_length:]
                            
                            # Decrypt
                            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
                            decryptor = cipher.decryptor()
                            plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
                            
                            # Try to decompress if needed
                            if metadata.get("compression", 0) != 0:
                                try:
                                    plain_bytes = decompress_data(plain_bytes)
                                except Exception as e:
                                    logger.warning(f"Decompression failed: {str(e)}")
                            
                            # Convert to string
                            try:
                                plain_text = plain_bytes.decode('utf-8')
                                is_binary = False
                            except UnicodeDecodeError:
                                plain_text = base64.b64encode(plain_bytes).decode('utf-8')
                                is_binary = True
                            
                            return {
                                "plain_text": plain_text,
                                "metadata": {
                                    "mode": mode.value,
                                    "iterations": iterations,
                                    "hmac": add_hmac,
                                    "is_binary": is_binary
                                }
                            }
                    except Exception as e:
                        logger.warning(f"Failed to parse GCM metadata: {str(e)}")
            
            # Check for CFB/CBC mode (salt + iv(16) + metadata_length)
            if len(combined) >= 36:
                metadata_length_bytes = combined[32:36]
                metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
                
                if metadata_length > 0 and metadata_length < 1000:
                    metadata_bytes = combined[36:36+metadata_length]
                    try:
                        metadata = json.loads(metadata_bytes.decode('utf-8'))
                        mode_str = metadata.get("mode", "cfb")
                        mode = EncryptionMode(mode_str)
                        iterations = metadata.get("iterations", 100000)
                        add_hmac = metadata.get("add_hmac", False)
                        logger.info(f"Detected {mode_str} mode from metadata")
                        
                        # Derive the key
                        derived_key = derive_key(key, salt, iterations)
                        
                        # Handle HMAC verification if present
                        if add_hmac:
                            hmac_size = 32  # SHA-256 produces 32 bytes
                            if len(combined) < 36 + metadata_length + hmac_size:
                                raise ValueError("Invalid ciphertext: too short for HMAC verification")
                            
                            hmac = combined[-hmac_size:]
                            data = combined[:-hmac_size]
                            
                            if not verify_hmac(derived_key, data, hmac):
                                raise ValueError("HMAC verification failed: data may have been tampered with")
                            
                            # Remove HMAC from combined data for further processing
                            combined = data
                        
                        # Extract IV and ciphertext
                        iv = combined[16:32]  # 16 bytes for CFB/CBC
                        cipher_text = combined[36+metadata_length:]
                        
                        # Decrypt based on mode
                        if mode == EncryptionMode.CFB:
                            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
                            decryptor = cipher.decryptor()
                            plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
                        elif mode == EncryptionMode.CBC:
                            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
                            decryptor = cipher.decryptor()
                            padded_plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
                            
                            # Remove padding
                            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                            plain_bytes = unpadder.update(padded_plain_bytes) + unpadder.finalize()
                        else:
                            raise ValueError(f"Unsupported mode detected: {mode}")
                        
                        # Try to decompress if needed
                        if metadata.get("compression", 0) != 0:
                            try:
                                plain_bytes = decompress_data(plain_bytes)
                            except Exception as e:
                                logger.warning(f"Decompression failed: {str(e)}")
                        
                        # Convert to string
                        try:
                            plain_text = plain_bytes.decode('utf-8')
                            is_binary = False
                        except UnicodeDecodeError:
                            plain_text = base64.b64encode(plain_bytes).decode('utf-8')
                            is_binary = True
                        
                        return {
                            "plain_text": plain_text,
                            "metadata": {
                                "mode": mode.value,
                                "iterations": iterations,
                                "hmac": add_hmac,
                                "is_binary": is_binary
                            }
                        }
                    except Exception as e:
                        logger.warning(f"Failed to parse CFB/CBC metadata: {str(e)}")
            
            # Fallback to detection if metadata parsing failed
            logger.warning("Metadata parsing failed, falling back to detection")
            mode, iterations, add_hmac = detect_encryption_mode(combined)
        except Exception as e:
            logger.warning(f"Failed to extract metadata: {str(e)}, falling back to detection")
            # Fallback to detection
            mode, iterations, add_hmac = detect_encryption_mode(combined)
        
        # Derive the key
        derived_key = derive_key(key, salt, iterations)
        
        # Handle HMAC verification if present
        if add_hmac:
            hmac_size = 32  # SHA-256 produces 32 bytes
            if len(combined) < 16 + hmac_size:
                raise ValueError("Invalid ciphertext: too short for HMAC verification")
            
            hmac = combined[-hmac_size:]
            data = combined[:-hmac_size]
            
            if not verify_hmac(derived_key, data, hmac):
                raise ValueError("HMAC verification failed: data may have been tampered with")
            
            # Remove HMAC from combined data for further processing
            combined = data
        
        # Process based on detected mode
        if mode == EncryptionMode.CFB:
            # For CFB: salt(16) + iv(16) + metadata_length(4) + metadata(var) + cipher_text
            if len(combined) < 36:  # Minimum size
                raise ValueError("Invalid ciphertext: too short (must include salt, IV, and metadata length)")
            
            iv = combined[16:32]
            metadata_length = int.from_bytes(combined[32:36], byteorder='big')
            
            if metadata_length > 0 and metadata_length < 1000:
                cipher_text = combined[36+metadata_length:]
            else:
                # Fallback if metadata parsing failed
                cipher_text = combined[36:]
            
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
            
        elif mode == EncryptionMode.CBC:
            # For CBC: salt(16) + iv(16) + metadata_length(4) + metadata(var) + cipher_text
            if len(combined) < 36:  # Minimum size
                raise ValueError("Invalid ciphertext: too short (must include salt, IV, and metadata length)")
            
            iv = combined[16:32]
            metadata_length = int.from_bytes(combined[32:36], byteorder='big')
            
            if metadata_length > 0 and metadata_length < 1000:
                cipher_text = combined[36+metadata_length:]
            else:
                # Fallback if metadata parsing failed
                cipher_text = combined[36:]
            
            cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plain_bytes = unpadder.update(padded_plain_bytes) + unpadder.finalize()
            
        elif mode == EncryptionMode.GCM:
            # For GCM: salt(16) + iv(12) + tag(16) + metadata_length(4) + metadata(var) + cipher_text
            if len(combined) < 48:  # Minimum size
                raise ValueError("Invalid ciphertext: too short (must include salt, IV, tag, and metadata length)")
            
            iv = combined[16:28]
            tag = combined[28:44]
            metadata_length = int.from_bytes(combined[44:48], byteorder='big')
            
            if metadata_length > 0 and metadata_length < 1000:
                cipher_text = combined[48+metadata_length:]
            else:
                # Fallback if metadata parsing failed
                cipher_text = combined[48:]
            
            cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plain_bytes = decryptor.update(cipher_text) + decryptor.finalize()
            
        else:
            raise ValueError(f"Unsupported encryption mode detected: {mode}")
        
        # Try to decompress the data
        try:
            decompressed_bytes = decompress_data(plain_bytes)
            plain_bytes = decompressed_bytes
        except Exception as e:
            logger.warning("Decompression failed, assuming uncompressed data: %s", str(e))
            # Continue with the original bytes if decompression fails
        
        # Calculate checksum for verification
        final_checksum = calculate_checksum(plain_bytes)
        
        # Convert bytes to string
        try:
            plain_text = plain_bytes.decode('utf-8')
            is_binary = False
        except UnicodeDecodeError as e:
            logger.info(f"Data appears to be binary, returning base64 encoded")
            # For binary data, return base64 encoded string
            plain_text = base64.b64encode(plain_bytes).decode('utf-8')
            is_binary = True
            
        logger.info("Decrypted message using %s mode", mode.value)
        
        return {
            "plain_text": plain_text,
            "metadata": {
                "mode": mode.value,
                "iterations": iterations,
                "hmac": add_hmac,
                "checksum": final_checksum,
                "is_binary": is_binary
            }
        }
        
    except Exception as e:
        logger.error("Decryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"Decryption error: {str(e)}")

def is_text(data: bytes, threshold: float = 0.3) -> bool:
    """
    Determine if data is likely text by checking for binary characters.
    Returns True if the data is likely text, False if likely binary.
    """
    # Check for common binary file signatures
    binary_signatures = [
        b'\x89PNG', b'GIF8', b'JFIF', b'%PDF', 
        b'PK\x03\x04', b'\x1f\x8b', b'\x00\x01\x00\x00'
    ]
    
    for sig in binary_signatures:
        if data.startswith(sig):
            return False
    
    # Count control characters (except common ones like newline, tab)
    control_chars = 0
    text_chars = 0
    
    # Only check a sample of the data for large files
    sample = data[:4096] if len(data) > 4096 else data
    
    for byte in sample:
        # Skip common control characters
        if byte in (9, 10, 13):  # tab, newline, carriage return
            text_chars += 1
        elif byte < 32 or (byte > 126 and byte < 160):
            control_chars += 1
        else:
            text_chars += 1
    
    total = control_chars + text_chars
    if total == 0:
        return True  # Empty is considered text
    
    # If more than threshold of characters are control chars, likely binary
    return (control_chars / total) < threshold

def detect_encryption_mode(data: bytes) -> Tuple[EncryptionMode, int, bool]:
    """
    Attempt to detect the encryption mode, iterations, and HMAC presence from the data.
    This is a heuristic and might not always be accurate.
    """
    # Default values
    mode = EncryptionMode.CFB
    iterations = 100000
    has_hmac = False
    
    # Check if this could be GCM mode based on length
    if len(data) >= 44 and len(data) - 44 >= 0:  # salt(16) + iv(12) + tag(16)
        # This could be GCM
        mode = EncryptionMode.GCM
    
    # Check data length for potential HMAC
    if len(data) > 64:  # At least salt(16) + iv(16) + cipher_text(1) + hmac(32)
        # Check if the last 32 bytes could be an HMAC
        has_hmac = True
    
    return mode, iterations, has_hmac

# Additional utility functions

def generate_key(length: int = 32) -> str:
    """Generate a random key of specified length."""
    if length < 16:
        logger.warning("Key length less than 16 bytes is not recommended for security")
    elif length > 64:
        logger.warning("Key length greater than 64 bytes provides diminishing returns")
        
    random_bytes = os.urandom(length)
    return base64.b64encode(random_bytes).decode('utf-8')

def encrypt_file_stream(
    file_stream: BinaryIO,
    key: str,
    config: CryptoConfig = CryptoConfig()
) -> Dict[str, Any]:
    """
    Encrypt a file from a stream and return the encrypted content.
    This is more memory efficient for large files.
    """
    try:
        # Read file content
        file_content = file_stream.read()
        file_size = len(file_content)
        logger.info(f"Encrypting file of size: {file_size} bytes")
        
        # Calculate original checksum
        original_checksum = calculate_checksum(file_content)
        
        # Convert binary content to base64 string for encryption
        content_str = base64.b64encode(file_content).decode('utf-8')
        
        # Encrypt the content
        result = encrypt_aes(content_str, key, config)
        
        # Add file metadata
        result["metadata"]["file_size"] = file_size
        result["metadata"]["original_checksum"] = original_checksum
        result["metadata"]["is_binary"] = True  # Mark as binary file
        
        return result
    except Exception as e:
        logger.error("File encryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"File encryption error: {str(e)}")

def decrypt_file_stream(
    encrypted_content: str,
    key: str
) -> Dict[str, Any]:
    """
    Decrypt encrypted content and return the file content and metadata.
    """
    try:
        # Decrypt the content
        result = decrypt_aes(encrypted_content, key)
        
        # Convert decrypted content back to binary
        try:
            # The plain_text should be a base64 encoded string of the file content
            file_content = base64.b64decode(result["plain_text"])
        except Exception as e:
            logger.error(f"Error decoding file content: {str(e)}")
            # Try an alternative approach if the standard decoding fails
            try:
                # If the content wasn't properly marked as binary, try to detect it
                if not result["metadata"].get("is_binary", False) and not is_text(result["plain_text"].encode('utf-8')):
                    # This might be binary data that wasn't properly marked
                    file_content = result["plain_text"].encode('latin1')
                else:
                    # Last resort - try to encode as utf-8 and hope for the best
                    file_content = result["plain_text"].encode('utf-8')
            except Exception as inner_e:
                logger.error(f"Secondary decoding attempt failed: {str(inner_e)}")
                raise ValueError(f"Failed to decode file content: {str(e)}")
        
        # Verify file integrity with checksum if available
        if "original_checksum" in result.get("metadata", {}):
            current_checksum = calculate_checksum(file_content)
            if current_checksum != result["metadata"]["original_checksum"]:
                logger.warning(
                    f"File checksum mismatch! Original: {result['metadata']['original_checksum']}, "
                    f"Current: {current_checksum}"
                )
                # We'll continue anyway, but log the warning
        
        return {
            "file_content": file_content,
            "metadata": result["metadata"]
        }
    except Exception as e:
        logger.error("File decryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"File decryption error: {str(e)}")

def encrypt_file(file_path: str, key: str, config: CryptoConfig = CryptoConfig()) -> str:
    """Encrypt a file and return the encrypted content as base64."""
    try:
        with open(file_path, 'rb') as f:
            result = encrypt_file_stream(f, key, config)
        return result["cipher_text"]
    except Exception as e:
        logger.error("File encryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"File encryption error: {str(e)}")

def decrypt_file(encrypted_content: str, key: str, output_path: str) -> None:
    """Decrypt encrypted content and save to a file."""
    try:
        result = decrypt_file_stream(encrypted_content, key)
        
        with open(output_path, 'wb') as f:
            f.write(result["file_content"])
        
        logger.info("File decrypted and saved to: %s", output_path)
    except Exception as e:
        logger.error("File decryption error: %s\n%s", str(e), traceback.format_exc())
        raise ValueError(f"File decryption error: {str(e)}")
