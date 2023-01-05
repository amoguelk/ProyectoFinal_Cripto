import time
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


def sign(message : bytes):
  start = time.time()
  private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
  )
  signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  end = time.time()
  return {"time": end - start, "result": signature}