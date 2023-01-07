from algoritmos import chacha20, aes_ebc, aes_cbc, sha2, sha3
from algoritmos import rsa_oaep, rsa_pss, ecdsa_prime
from ctes.vectores import vectorsCypher
from ctes.plaintexts import pts

#ChaCha20
print('ChaCha20')
i = 0
for v in vectorsCypher:
  i += 1
  print(f'\tVector {i}:')
  ch20_1 = chacha20.encrypt(v[0], v[1], v[2])
  print('\t\tOperaciones de cifrado en un segundo: ', str(ch20_1['ops']))
  ch20_2 = chacha20.decrypt(v[0], v[1], ch20_1['result'])
  print('\t\tOperaciones de descifrado en un segundo: ', str(ch20_2['ops']), end='\n\n')

#AES-EBC
print('AES-EBC')
i = 0
for v in vectorsCypher:
  i += 1
  print(f'\tVector {i}:')
  aesEbc_1 = aes_ebc.encrypt(v[0], v[1], v[2])
  print('\t\tOperaciones de cifrado en un segundo: ', str(aesEbc_1['ops']))
  aesEbc_2 = aes_ebc.decrypt(v[0], v[1], aesEbc_1['result'])
  print('\t\tOperaciones de descifrado en un segundo: ', str(aesEbc_2['ops']), end='\n\n')

#AES-CBC
print('AES-CBC')
i = 0
for v in vectorsCypher:
  i += 1
  print(f'\tVector {i}:')
  aesCbc_1 = aes_cbc.encrypt(v[0], v[1], v[2])
  print('\t\tOperaciones de cifrado en un segundo: ', str(aesCbc_1['ops']))
  aesCbc_2 = aes_cbc.decrypt(v[0], v[1], aesCbc_1['result'])
  print('\t\tOperaciones de descifrado en un segundo: ', str(aesCbc_2['ops']), end='\n\n')

#SHA2
print('SHA-2')
i = 0
for p in pts:
  i += 1
  print(f'\tVector {i}:')
  sha2_1 = sha2.hash384(p)
  print('\t\tOperaciones hash de 384 bits en un segundo: ', str(sha2_1['ops']))
  sha2_2 = sha2.hash512(p)
  print('\t\tOperaciones hash de 512 bits en un segundo: ', str(sha2_2['ops']), end='\n\n')

#SHA3
print('SHA-3')
i = 0
for p in pts:
  i += 1
  print(f'\tVector {i}:')
  sha3_1 = sha3.hash384(p)
  print('\t\tOperaciones hash de 384 bits en un segundo: ', str(sha3_1['ops']))
  sha3_2 = sha3.hash512(p)
  print('\t\tOperaciones hash de 512 bits en un segundo: ', str(sha3_2['ops']), end='\n\n')

#RSA-OAEP
print('RSA-OAEP')
i = 0
for p in pts:
  i += 1
  print(f'\tVector {i}:')
  rsaOaep_1 = rsa_oaep.encrypt(p)
  print('\t\tOperaciones de cifrado en un segundo: ', str(rsaOaep_1['ops']))
  rsaOaep_2 = rsa_oaep.decrypt(rsaOaep_1['result'])
  print('\t\tOperaciones de cifrado en un segundo: ', str(rsaOaep_2['ops']), end='\n\n')

#RSA-PSS
print('RSA-PSS')
i = 0
for p in pts:
  i += 1
  print(f'\tVector {i}:')
  rsaPss = rsa_pss.sign(p)
  print('\t\tOperaciones de firmado en un segundo: ', str(rsaPss['ops']), end='\n\n')

#ECDSA - Prime Field
print('ECDSA (Prime Field)')
i = 0
for p in pts:
  i += 1
  print(f'\tVector {i}:')
  ecdsaPrime = ecdsa_prime.sign(p)
  print('\t\tOperaciones de firmado en un segundo: ', str(ecdsaPrime['ops']), end='\n\n')

#ECDSA - Binary Field
