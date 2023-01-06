import time, hashlib

def hash384(pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    result = hashlib.sha3_384(pt).hexdigest()
    count += 1
  return {"ops": count, "result": result}
  
def hash512(pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    result = hashlib.sha3_512(pt).hexdigest()
    count += 1
  return {"ops": count, "result": result}