import time, hashlib

def hash384(pt : bytes):
  start = time.time()
  result = hashlib.sha384(pt).hexdigest()
  end = time.time()
  return {"time": end - start, "result": result}
  
def hash512(pt : bytes):
  start = time.time()
  result = hashlib.sha512(pt).hexdigest()
  end = time.time()
  return {"time": end - start, "result": result}