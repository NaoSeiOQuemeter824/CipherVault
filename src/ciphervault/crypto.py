import os
import json
import struct
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

logger = logging.getLogger("ciphervault")


class KeyStore:
    """Gere o par de chaves RSA do utilizador em ~/.ciphervault"""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path.home() / ".ciphervault")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.private_key_path = self.base_dir / "private_key.pem"
        self.public_key_path = self.base_dir / "public_key.pem"
        self.private_key = None
        self.public_key = None
        logger.debug(f"KeyStore inicializado em: {self.base_dir}")

    def ensure_keys(self) -> None:
        if self.private_key_path.exists() and self.public_key_path.exists():
            logger.debug("Chaves encontradas no disco; a carregar par existente.")
            self._load()
        else:
            logger.debug("Nenhuma chave encontrada; a gerar novo par RSA-4096.")
            self._generate()

    def _generate(self) -> None:
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.public_key = self.private_key.public_key()

        self.private_key_path.write_bytes(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            os.chmod(self.private_key_path, 0o600)
        except Exception:
            pass
        logger.debug(f"Chave privada escrita: {self.private_key_path}")

        self.public_key_path.write_bytes(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        logger.debug(f"Chave pública escrita: {self.public_key_path}")

    def _load(self) -> None:
        self.private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(), password=None
        )
        self.public_key = self.private_key.public_key()
        logger.debug(f"Chave privada carregada de: {self.private_key_path}")
        logger.debug(f"Chave pública carregada de: {self.public_key_path}")

    def get_public_pem(self) -> bytes:
        if not self.public_key:
            self.ensure_keys()
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_fingerprint_hex(self) -> str:
        """Retorna a impressão digital SHA-256 da chave pública (hex)."""
        pub = self.get_public_pem()
        d = hashes.Hash(hashes.SHA256())
        d.update(pub)
        return d.finalize().hex()


class SelfEncryptor:
    """Cifrar/Decifrar para si usando RSA-4096 + AES-256-GCM.

    Formato do ficheiro (.cvault):
    - Magic: b"CVAULT" (6)
    - Versão: uint8 (1)
    - Flags: uint8 (1)  bit0: encrypted=1
    - Tamanho metadados: uint16 (2)
    - Metadados JSON (nome ficheiro, tamanho)
    - Tamanho chave pública PEM: uint16 (2)
    - Bytes da chave pública PEM
    - Tamanho chave AES cifrada: uint16 (2)
    - Bytes da chave AES cifrada
    - Tamanho assinatura: uint16 (2)
    - Bytes da assinatura (RSA-PSS sobre hash SHA-256 do plaintext)
    - Nonce (12)
    - Tag (16)
    - Ciphertext (restante)
    """

    MAGIC = b"CVAULT"
    VERSION = 1

    def __init__(self, keystore: Optional[KeyStore] = None):
        self.keystore = keystore or KeyStore()
        self.keystore.ensure_keys()

    def _key_id(self, public_pem: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_pem)
        return digest.finalize()[:16]

    def encrypt_file(self, input_path: Path, output_path: Optional[Path] = None) -> Path:
        input_path = Path(input_path)
        if not input_path.exists() or not input_path.is_file():
            raise FileNotFoundError(f"Ficheiro não encontrado: {input_path}")

        data = input_path.read_bytes()
        filename = input_path.name
        logger.debug(f"A cifrar ficheiro: {input_path} (tamanho={len(data)} bytes)")

        # 1) Generate AES key and nonce
        aes_key = os.urandom(32)  # 256-bit
        nonce = os.urandom(12)    # 96-bit recommended for GCM
        logger.debug("Gerada chave AES-256 e nonce GCM de 12 bytes.")

        # 2) Encrypt data with AES-256-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        logger.debug(f"Cifragem AES-GCM concluída. tag_len={len(tag)} bytes, ciphertext_len={len(ciphertext)} bytes.")

        # 3) Encrypt AES key with our own public key (self)
        encrypted_aes_key = self.keystore.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        logger.debug(f"Chave AES envolvida com RSA-OAEP. wrapped_len={len(encrypted_aes_key)} bytes.")

        # 4) Sign original plaintext hash with our private key
        d = hashes.Hash(hashes.SHA256())
        d.update(data)
        file_hash = d.finalize()
        signature = self.keystore.private_key.sign(
            file_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        logger.debug(f"Hash do plaintext assinado com RSA-PSS. signature_len={len(signature)} bytes.")

        # 5) Assemble .cvault
        public_pem = self.keystore.get_public_pem()
        fp = self.keystore.get_fingerprint_hex()
        metadata = {"filename": filename, "size": len(data)}
        metadata_json = json.dumps(metadata).encode("utf-8")

        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + ".cvault")

        with open(output_path, "wb") as f:
            f.write(self.MAGIC)
            f.write(struct.pack("B", self.VERSION))
            f.write(struct.pack("B", 0x01))  # encrypted flag
            f.write(struct.pack("H", len(metadata_json)))
            f.write(metadata_json)

            f.write(struct.pack("H", len(public_pem)))
            f.write(public_pem)

            f.write(struct.pack("H", len(encrypted_aes_key)))
            f.write(encrypted_aes_key)

            f.write(struct.pack("H", len(signature)))
            f.write(signature)

            f.write(nonce)
            f.write(tag)
            f.write(ciphertext)
        logger.debug(f"Ficheiro .cvault escrito: {output_path} (fp_chave_pub={fp[:16]}…)")
        return output_path

    def decrypt_file(self, vault_path: Path, output_path: Optional[Path] = None) -> Path:
        vault_path = Path(vault_path)
        if not vault_path.exists() or not vault_path.is_file():
            raise FileNotFoundError(f"Ficheiro não encontrado: {vault_path}")

        with open(vault_path, "rb") as f:
            magic = f.read(6)
            if magic != self.MAGIC:
                raise ValueError("Formato de ficheiro inválido (magic)")
            version = struct.unpack("B", f.read(1))[0]
            if version != self.VERSION:
                raise ValueError(f"Versão não suportada: {version}")
            flags = struct.unpack("B", f.read(1))[0]
            meta_len = struct.unpack("H", f.read(2))[0]
            metadata = json.loads(f.read(meta_len).decode("utf-8"))

            pub_len = struct.unpack("H", f.read(2))[0]
            public_pem = f.read(pub_len)

            key_len = struct.unpack("H", f.read(2))[0]
            encrypted_aes_key = f.read(key_len)

            sig_len = struct.unpack("H", f.read(2))[0]
            signature = f.read(sig_len)

            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()
        logger.debug(
            "Ficheiro .cvault lido: meta=%s, pub_len=%d, wrapped_len=%d, sig_len=%d, nonce_len=%d, tag_len=%d, ciphertext_len=%d",
            metadata,
            pub_len,
            key_len,
            sig_len,
            len(nonce),
            len(tag),
            len(ciphertext),
        )

        # Check it's our file (encrypted for self)
        my_pub_pem = self.keystore.get_public_pem()
        if public_pem != my_pub_pem:
            raise PermissionError("Este ficheiro não foi cifrado com a SUA chave pública.")
        else:
            logger.debug("Chave pública embutida coincide com a chave local (fingerprint=%s).", self.keystore.get_fingerprint_hex()[:32])

        # Decrypt AES key with our private key
        aes_key = self.keystore.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        logger.debug("Chave AES recuperada com RSA-OAEP.")

        # Decrypt data
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        logger.debug("Decifragem AES-GCM finalizada.")

        # Verify signature
        sender_pub = serialization.load_pem_public_key(public_pem)
        d = hashes.Hash(hashes.SHA256())
        d.update(plaintext)
        file_hash = d.finalize()
        try:
            sender_pub.verify(
                signature,
                file_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as e:
            # Assinatura inválida: alerta e falha
            raise ValueError("Assinatura inválida: ficheiro alterado ou chave incorreta") from e
        logger.debug("Assinatura verificada com sucesso (RSA-PSS/SHA-256).")

        # Determine output path
        if output_path is None:
            output_path = vault_path.parent / metadata.get("filename", vault_path.stem)

        Path(output_path).write_bytes(plaintext)
        logger.debug(f"Ficheiro decifrado escrito: {output_path} (tamanho={len(plaintext)} bytes)")
        return output_path
