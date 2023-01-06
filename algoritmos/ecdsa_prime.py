import time
from ecdsa import SigningKey, NIST256p

def sign(message : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    sk = SigningKey.generate(curve=NIST256p)
    signature = sk.sign(message)
    count += 1
  return {"ops": count, "result": signature}