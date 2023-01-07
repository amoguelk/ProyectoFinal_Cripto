import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key : bytes, iv : bytes, pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()
    count += 1
  return {"ops": count, "result": ct}
  
def decrypt(key : bytes, iv : bytes, ct : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    count += 1
  return {"ops": count, "result": pt}
  