import time
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
  )

def encrypt(pt : bytes):
  start = time.time()
  public_key = private_key.public_key()
  ct = public_key.encrypt(
      pt,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  end = time.time()
  return {"time": end - start, "result": ct}

def decrypt(ct : bytes):
  start = time.time()
  pt = private_key.decrypt(
      ct,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )

  print()
  end = time.time()
  return {"time": end - start, "result": pt}