import os
from algoritmos import chacha20, aes_ebc, aes_cbc, sha2, sha3
from algoritmos import rsa_oaep, rsa_pss, ecdsa_prime
key = os.urandom(32)
iv = os.urandom(16)

pt = b'a secret message'
message = b'A message I want to sign'

#ChaCha20
print('ChaCha20')
ch20_1 = chacha20.encrypt(key, iv, pt)
print('\tOperaciones de cifrado en un segundo: ', str(ch20_1['ops']))
ch20_2 = chacha20.decrypt(key, iv, ch20_1['result'])
print('\tOperaciones de descifrado en un segundo: ', str(ch20_2['ops']), end='\n\n')

#AES-EBC
print('AES-EBC')
aesEbc_1 = aes_ebc.encrypt(key, iv, pt)
print('\tOperaciones de cifrado en un segundo: ', str(aesEbc_1['ops']))
aesEbc_2 = aes_ebc.decrypt(key, iv, ch20_1['result'])
print('\tOperaciones de descifrado en un segundo: ', str(aesEbc_2['ops']), end='\n\n')

#AES-CBC
print('AES-CBC')
aesCbc_1 = aes_cbc.encrypt(key, iv, pt)
print('\tOperaciones de cifrado en un segundo: ', str(aesCbc_1['ops']))
aesCbc_2 = aes_cbc.decrypt(key, iv, ch20_1['result'])
print('\tOperaciones de descifrado en un segundo: ', str(aesCbc_2['ops']), end='\n\n')

#SHA2
print('SHA-2')
sha2_1 = sha2.hash384(pt)
print('\tOperaciones hash de 384 bits en un segundo: ', str(sha2_1['ops']))
sha2_2 = sha2.hash512(pt)
print('\tOperaciones hash de 512 bits en un segundo: ', str(sha2_2['ops']), end='\n\n')

#SHA3
print('SHA-3')
sha3_1 = sha3.hash384(pt)
print('\tOperaciones hash de 384 bits en un segundo: ', str(sha3_1['ops']))
sha3_2 = sha3.hash512(pt)
print('\tOperaciones hash de 512 bits en un segundo: ', str(sha3_2['ops']), end='\n\n')

#RSA-OAEP
print('RSA-OAEP')
rsaOaep_1 = rsa_oaep.encrypt(pt)
print('\tOperaciones de cifrado en un segundo: ', str(rsaOaep_1['ops']))
rsaOaep_2 = rsa_oaep.decrypt(rsaOaep_1['result'])
print('\tOperaciones de cifrado en un segundo: ', str(rsaOaep_2['ops']), end='\n\n')

#RSA-PSS
print('RSA-PSS')
rsaPss = rsa_pss.sign(message)
print('\tOperaciones de firmado en un segundo: ', str(rsaPss['ops']), end='\n\n')

#ECDSA - Prime Field
print('ECDSA (Prime Field)')
ecdsaPrime = ecdsa_prime.sign(message)
print('\tOperaciones de firmado en un segundo: ', str(ecdsaPrime['ops']), end='\n\n')

#ECDSA - Binary Field
