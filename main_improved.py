from fastapi import FastAPI, HTTPException, UploadFile, File, Form, BackgroundTasks, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import os
import uuid
import logging
import traceback
import time
from enum import Enum
import tempfile
import shutil
import io
import base64
import json
from crypto_improved import (
    encrypt_aes, decrypt_aes, CryptoConfig, EncryptionMode, 
    CompressionLevel, generate_key, encrypt_file_stream, decrypt_file_stream,
    calculate_checksum
)
from asymmetric_crypto import AsymmetricCrypto

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create temp directory for file operations
TEMP_DIR = tempfile.mkdtemp()
logger.info(f"Created temporary directory: {TEMP_DIR}")

# Maximum file size (100MB by default)
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Cleanup function for background tasks
def cleanup_temp_file(file_path: str):
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Cleaned up temporary file: {file_path}")
    except Exception as e:
        logger.error(f"Error cleaning up file {file_path}: {str(e)}")

app = FastAPI(
    title="AES Encryption API",
    description="API for AES encryption and decryption of text and files",
    version="2.3.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

class EncryptionModeEnum(str, Enum):
    CFB = "cfb"
    CBC = "cbc"
    GCM = "gcm"

class CompressionLevelEnum(int, Enum):
    NONE = 0
    FAST = 1
    DEFAULT = 6
    BEST = 9

class AESTextPayload(BaseModel):
    message: str
    key: str
    mode: Optional[EncryptionModeEnum] = EncryptionModeEnum.CFB
    compression: Optional[CompressionLevelEnum] = CompressionLevelEnum.NONE
    iterations: Optional[int] = Field(default=100000, ge=10000, le=1000000)
    add_hmac: Optional[bool] = False

class RSAKeyGenPayload(BaseModel):
    key_size: Optional[int] = Field(default=2048, ge=2048, le=4096)

class RSAEncryptPayload(BaseModel):
    recipient_public_key: str
    sender_private_key: Optional[str] = None

class RSADecryptPayload(BaseModel):
    encrypted_data: Dict[str, Any]
    recipient_private_key: str
    sender_public_key: Optional[str] = None

class AESResponse(BaseModel):
    status: str
    message: str
    data: Dict[str, Any]
    processing_time: float

@app.get("/")
async def health_check():
    logger.info("Health check requested")
    return {"status": "ok", "version": "2.3.0"}

@app.get("/generate-key")
async def generate_encryption_key(length: int = 32):
    """Generate a random encryption key."""
    start_time = time.time()
    try:
        if length < 16:
            raise HTTPException(status_code=400, detail="Key length must be at least 16 bytes for security")
        if length > 64:
            raise HTTPException(status_code=400, detail="Key length must not exceed 64 bytes")
            
        key = generate_key(length)
        processing_time = time.time() - start_time
        
        return AESResponse(
            status="success",
            message="Key generated successfully",
            data={"key": key},
            processing_time=processing_time
        )
    except Exception as e:
        logger.error("Key generation failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")

@app.post("/encrypt")
async def encrypt(payload: AESTextPayload):
    """Encrypt text using AES."""
    start_time = time.time()
    try:
        logger.info("Encrypt endpoint called with mode: %s, compression: %s", 
                   payload.mode, payload.compression)
        
        # Validate input
        if not payload.message:
            raise HTTPException(status_code=400, detail="Message cannot be empty")
        if not payload.key:
            raise HTTPException(status_code=400, detail="Key cannot be empty")
        
        # Create config from payload
        config = CryptoConfig(
            mode=EncryptionMode(payload.mode),
            iterations=payload.iterations,
            compression=CompressionLevel(payload.compression),
            add_hmac=payload.add_hmac
        )
        
        # Encrypt the message
        result = encrypt_aes(payload.message, payload.key, config)
        processing_time = time.time() - start_time
        
        logger.info("Encryption successful, processing time: %.2f seconds", processing_time)
        
        return AESResponse(
            status="success",
            message="Text encrypted successfully",
            data=result,
            processing_time=processing_time
        )
    except Exception as e:
        logger.error("Encryption failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"Encryption failed: {str(e)}")

@app.post("/decrypt")
async def decrypt(payload: AESTextPayload):
    """Decrypt text using AES."""
    start_time = time.time()
    try:
        logger.info("Decrypt endpoint called")
        
        # Validate input
        if not payload.message:
            raise HTTPException(status_code=400, detail="Encrypted message cannot be empty")
        if not payload.key:
            raise HTTPException(status_code=400, detail="Key cannot be empty")
        
        # Decrypt the message
        result = decrypt_aes(payload.message, payload.key)
        processing_time = time.time() - start_time
        
        logger.info("Decryption successful, processing time: %.2f seconds", processing_time)
        
        return AESResponse(
            status="success",
            message="Text decrypted successfully",
            data=result,
            processing_time=processing_time
        )
    except Exception as e:
        logger.error("Decryption failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.post("/encrypt-file")
async def encrypt_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    key: str = Form(...),
    mode: EncryptionModeEnum = Form(EncryptionModeEnum.CFB),
    compression: CompressionLevelEnum = Form(CompressionLevelEnum.DEFAULT),
    iterations: int = Form(100000),
    add_hmac: bool = Form(False)
):
    """Encrypt a file using AES."""
    start_time = time.time()
    temp_file_path = None
    
    try:
        # Validate file size
        file_size = 0
        chunk_size = 1024 * 1024  # 1MB chunks for reading
        
        # Generate a unique file ID and path
        file_id = str(uuid.uuid4())
        temp_file_path = os.path.join(TEMP_DIR, f"{file_id}_{file.filename}")
        
        # Save uploaded file to temp directory
        with open(temp_file_path, "wb") as buffer:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413, 
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE/(1024*1024)}MB"
                    )
                buffer.write(chunk)
        
        logger.info(f"File saved temporarily at: {temp_file_path}, size: {file_size} bytes")
        
        # Create config from form data
        config = CryptoConfig(
            mode=EncryptionMode(mode),
            iterations=iterations,
            compression=CompressionLevel(compression),
            add_hmac=add_hmac
        )
        
        # Encrypt the file
        with open(temp_file_path, "rb") as f:
            result = encrypt_file_stream(f, key, config)
        
        processing_time = time.time() - start_time
        
        # Add file metadata
        result["metadata"]["original_filename"] = file.filename
        result["metadata"]["file_size"] = file_size
        result["metadata"]["content_type"] = file.content_type or "application/octet-stream"
        
        # Schedule cleanup of temp file
        background_tasks.add_task(cleanup_temp_file, temp_file_path)
        
        logger.info("File encryption successful, processing time: %.2f seconds", processing_time)
        
        return AESResponse(
            status="success",
            message="File encrypted successfully",
            data=result,
            processing_time=processing_time
        )
    except Exception as e:
        # Ensure temp file is cleaned up even on error
        if temp_file_path and os.path.exists(temp_file_path):
            background_tasks.add_task(cleanup_temp_file, temp_file_path)
        
        logger.error("File encryption failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"File encryption failed: {str(e)}")

@app.post("/decrypt-file")
async def decrypt_file(
    background_tasks: BackgroundTasks,
    cipher_text: str = Form(...),
    key: str = Form(...),
    original_filename: Optional[str] = Form(None),
    content_type: Optional[str] = Form(None)
):
    """Decrypt a file using AES and return the decrypted file."""
    start_time = time.time()
    output_file_path = None
    
    try:
        # Decrypt the content
        result = decrypt_file_stream(cipher_text, key)
        file_content = result["file_content"]
        
        # Generate a filename for the decrypted file
        file_id = str(uuid.uuid4())
        filename = original_filename or f"decrypted_file_{file_id}"
        output_file_path = os.path.join(TEMP_DIR, filename)
        
        # Save the decrypted content to a file
        with open(output_file_path, "wb") as f:
            f.write(file_content)
        
        processing_time = time.time() - start_time
        logger.info("File decryption successful, processing time: %.2f seconds", processing_time)
        
        # Calculate checksum for verification
        file_checksum = calculate_checksum(file_content)
        logger.info(f"Decrypted file checksum: {file_checksum}")
        
        # Determine content type
        file_content_type = content_type or result["metadata"].get("content_type", "application/octet-stream")
        
        # Return the file as a download
        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
        
        # Schedule cleanup of the output file after it's been sent
        background_tasks.add_task(cleanup_temp_file, output_file_path)
        
        return FileResponse(
            path=output_file_path,
            filename=filename,
            media_type=file_content_type,
            headers=headers
        )
    except Exception as e:
        # Ensure temp files are cleaned up even on error
        if output_file_path and os.path.exists(output_file_path):
            background_tasks.add_task(cleanup_temp_file, output_file_path)
        
        logger.error("File decryption failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"File decryption failed: {str(e)}")

# New endpoints for asymmetric encryption

@app.post("/generate-rsa-keypair")
async def generate_rsa_keypair(payload: RSAKeyGenPayload):
    """Generate an RSA key pair for asymmetric encryption."""
    start_time = time.time()
    try:
        logger.info(f"Generate RSA key pair endpoint called with key size: {payload.key_size}")
        
        public_key, private_key = AsymmetricCrypto.generate_key_pair(payload.key_size)
        processing_time = time.time() - start_time
        
        logger.info("RSA key pair generation successful, processing time: %.2f seconds", processing_time)
        
        return AESResponse(
            status="success",
            message="RSA key pair generated successfully",
            data={
                "public_key": public_key,
                "private_key": private_key
            },
            processing_time=processing_time
        )
    except Exception as e:
        logger.error("RSA key pair generation failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"RSA key pair generation failed: {str(e)}")

@app.post("/encrypt-file-with-rsa")
async def encrypt_file_with_rsa(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    recipient_public_key: str = Form(...),
    sender_private_key: Optional[str] = Form(None)
):
    """
    Encrypt a file using hybrid encryption (RSA + AES).
    The file is encrypted with AES, and the AES key is encrypted with the recipient's RSA public key.
    """
    start_time = time.time()
    temp_file_path = None
    
    try:
        # Log the received keys for debugging (remove sensitive parts)
        logger.info(f"Received public key starting with: {recipient_public_key[:50]}...")
        if sender_private_key:
            logger.info(f"Received private key starting with: {sender_private_key[:50]}...")
        
        # Validate file size
        file_size = 0
        chunk_size = 1024 * 1024  # 1MB chunks for reading
        
        # Generate a unique file ID and path
        file_id = str(uuid.uuid4())
        temp_file_path = os.path.join(TEMP_DIR, f"{file_id}_{file.filename}")
        
        # Save uploaded file to temp directory
        with open(temp_file_path, "wb") as buffer:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413, 
                        detail=f"File too large. Maximum size is {MAX_FILE_SIZE/(1024*1024)}MB"
                    )
                buffer.write(chunk)
        
        logger.info(f"File saved temporarily at: {temp_file_path}, size: {file_size} bytes")
        
        # Read the file
        with open(temp_file_path, "rb") as f:
            file_data = f.read()
        
        # Encrypt the file for the recipient
        result = AsymmetricCrypto.encrypt_file_for_recipient(
            file_data,
            recipient_public_key,
            sender_private_key
        )
        
        # Add file metadata
        result["original_filename"] = file.filename
        result["file_size"] = file_size
        result["content_type"] = file.content_type or "application/octet-stream"
        
        processing_time = time.time() - start_time
        
        # Schedule cleanup of temp file
        background_tasks.add_task(cleanup_temp_file, temp_file_path)
        
        logger.info("File encryption with RSA successful, processing time: %.2f seconds", processing_time)
        
        return AESResponse(
            status="success",
            message="File encrypted successfully with RSA",
            data=result,
            processing_time=processing_time
        )
    except Exception as e:
        # Ensure temp file is cleaned up even on error
        if temp_file_path and os.path.exists(temp_file_path):
            background_tasks.add_task(cleanup_temp_file, temp_file_path)
        
        logger.error("File encryption with RSA failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"File encryption with RSA failed: {str(e)}")

@app.post("/decrypt-file-with-rsa")
async def decrypt_file_with_rsa(
    background_tasks: BackgroundTasks,
    payload: str = Form(...)
):
    """
    Decrypt a file that was encrypted with hybrid encryption (RSA + AES).
    The AES key is decrypted with the recipient's RSA private key, then the file is decrypted with the AES key.
    """
    start_time = time.time()
    output_file_path = None
    
    try:
        # Parse the payload
        try:
            logger.info(f"Received payload string of length: {len(payload)}")
            logger.info(f"Payload preview: {payload[:100]}...")
            
            payload_data = json.loads(payload)
            
            encrypted_data = payload_data.get("encrypted_data", {})
            recipient_private_key = payload_data.get("recipient_private_key", "")
            sender_public_key = payload_data.get("sender_public_key")
            
            if not encrypted_data:
                raise ValueError("Missing encrypted_data in payload")
            if not recipient_private_key:
                raise ValueError("Missing recipient_private_key in payload")
                
            logger.info(f"Encrypted data keys: {list(encrypted_data.keys())}")
            logger.info(f"Recipient private key length: {len(recipient_private_key)}")
            if sender_public_key:
                logger.info(f"Sender public key length: {len(sender_public_key)}")
        except Exception as e:
            logger.error(f"Error parsing payload: {str(e)}\n{traceback.format_exc()}")
            raise ValueError(f"Invalid payload format: {str(e)}")
        
        # Decrypt the file
        result = AsymmetricCrypto.decrypt_file_from_sender(
            encrypted_data,
            recipient_private_key,
            sender_public_key
        )
        
        decrypted_file = result["decrypted_file"]
        signature_verified = result["signature_verified"]
        
        # Generate a filename for the decrypted file
        file_id = str(uuid.uuid4())
        original_filename = encrypted_data.get("original_filename", f"decrypted_file_{file_id}")
        output_file_path = os.path.join(TEMP_DIR, original_filename)
        
        # Save the decrypted content to a file
        with open(output_file_path, "wb") as f:
            f.write(decrypted_file)
        
        processing_time = time.time() - start_time
        
        logger.info("File decryption with RSA successful, processing time: %.2f seconds", processing_time)
        logger.info(f"Signature verified: {signature_verified}")
        
        # Determine content type
        content_type = encrypted_data.get("content_type", "application/octet-stream")
        
        # Return the file as a download
        headers = {
            "Content-Disposition": f'attachment; filename="{original_filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
            "X-Signature-Verified": str(signature_verified) if signature_verified is not None else "unsigned"
        }
        
        # Schedule cleanup of the output file after it's been sent
        background_tasks.add_task(cleanup_temp_file, output_file_path)
        
        return FileResponse(
            path=output_file_path,
            filename=original_filename,
            media_type=content_type,
            headers=headers
        )
    except Exception as e:
        # Ensure temp files are cleaned up even on error
        if output_file_path and os.path.exists(output_file_path):
            background_tasks.add_task(cleanup_temp_file, output_file_path)
        
        logger.error("File decryption with RSA failed: %s\n%s", str(e), traceback.format_exc())
        raise HTTPException(status_code=400, detail=f"File decryption with RSA failed: {str(e)}")

@app.on_event("shutdown")
def cleanup_temp_dir():
    """Clean up the temporary directory when the application shuts down."""
    try:
        shutil.rmtree(TEMP_DIR)
        logger.info(f"Cleaned up temporary directory: {TEMP_DIR}")
    except Exception as e:
        logger.error(f"Error cleaning up directory {TEMP_DIR}: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
