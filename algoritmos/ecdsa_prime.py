import time
from ecdsa import SigningKey

def sign(message : bytes):
  start = time.time()
  sk = SigningKey.generate() # uses NIST192p
  signature = sk.sign(message)
  end = time.time()
  return {"time": end - start, "result": signature}