import time
from ecdsa import SigningKey, NIST256p

def sign(message : bytes):
  start = time.time()
  sk = SigningKey.generate(curve=NIST256p)
  signature = sk.sign(message)
  print(len(signature))
  end = time.time()
  return {"time": end - start, "result": signature}