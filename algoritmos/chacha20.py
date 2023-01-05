import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(key : bytes, iv : bytes, pt : bytes):
  start = time.time()
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  encryptor = cipher.encryptor()
  ct = encryptor.update(pt) + encryptor.finalize()
  end = time.time()
  return {"time": end - start, "result": ct}
  
def decrypt(key : bytes, iv : bytes, ct : bytes):
  start = time.time()
  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  pt = decryptor.update(ct) + decryptor.finalize()
  end = time.time()
  return {"time": end - start, "result": pt}