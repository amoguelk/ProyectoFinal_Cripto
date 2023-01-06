import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key : bytes, iv : bytes, pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    buf = bytearray(31)
    len_encrypted = encryptor.update_into(pt, buf)
    ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
    count += 1
  return {"ops": count, "result": ct}

def decrypt(key : bytes, iv : bytes, ct : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    buf = bytearray(31)
    len_decrypted = decryptor.update_into(ct, buf)
    pt = bytes(buf[:len_decrypted]) + decryptor.finalize()
    count += 1
  return {"ops": count, "result": pt}