import time, hashlib

def hash384(pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    result = hashlib.sha384(pt).hexdigest()
    count += 1
  return {"ops": count, "result": result}
  
def hash512(pt : bytes):
  count = 0
  end = time.time() + 1
  while time.time() < end:
    result = hashlib.sha512(pt).hexdigest()
    count += 1
  return {"ops": count, "result": result}