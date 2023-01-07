from ctes.llaves import keys
from ctes.plaintexts import pts
from ctes.nonces import nonces

vectorsCypher = []

for i in range(len(pts)):
  vectorsCypher.append([keys[i], nonces[i], pts[i]])