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
print('\tTiempo de cifrado con ChaCha20: ', str(ch20_1['time']))
ch20_2 = chacha20.decrypt(key, iv, ch20_1['result'])
print('\tTiempo de descifrado con ChaCha20: ', str(ch20_2['time']), end='\n\n')

#AES-EBC
print('AES-EBC')
aesEbc_1 = aes_ebc.encrypt(key, iv, pt)
print('\tTiempo de cifrado con AES-EBC: ', str(aesEbc_1['time']))
aesEbc_2 = aes_ebc.decrypt(key, iv, ch20_1['result'])
print('\tTiempo de descifrado con AES-EBC: ', str(aesEbc_2['time']), end='\n\n')

#AES-CBC
print('AES-CBC')
aesCbc_1 = aes_cbc.encrypt(key, iv, pt)
print('\tTiempo de cifrado con AES-CBC: ', str(aesCbc_1['time']))
aesCbc_2 = aes_cbc.decrypt(key, iv, ch20_1['result'])
print('\tTiempo de descifrado con AES-CBC: ', str(aesCbc_2['time']), end='\n\n')

#SHA2
print('SHA-2')
sha2_1 = sha2.hash384(pt)
print('\tHash size 384 bits: ', str(sha2_1['time']))
sha2_2 = sha2.hash512(pt)
print('\tHash size 512 bits: ', str(sha2_2['time']), end='\n\n')

#SHA3
print('SHA-3')
sha3_1 = sha3.hash384(pt)
print('\tHash size 384 bits: ', str(sha3_1['time']))
sha3_2 = sha3.hash512(pt)
print('\tHash size 512 bits: ', str(sha3_2['time']), end='\n\n')

#RSA-OAEP
print('RSA-OAEP')
rsaOaep_1 = rsa_oaep.encrypt(pt)
print('\tTiempo de cifrado con RSA-OAEP: ', str(rsaOaep_1['time']))
rsaOaep_2 = rsa_oaep.decrypt(rsaOaep_1['result'])
print('\tTiempo de descifrado con RSA-OAEP: ', str(rsaOaep_2['time']), end='\n\n')

#RSA-PSS
print('RSA-PSS')
rsaPss = rsa_pss.sign(message)
print('\tTiempo de firmado con RSA-PSS: ', str(rsaPss['time']), end='\n\n')

#ECDSA - Prime Field
print('ECDSA (Prime Field)')
ecdsaPrime = ecdsa_prime.sign(message)
print('\tTiempo de firmado con ECDSA (Prime Field): ', str(ecdsaPrime['time']), end='\n\n')

#ECDSA - Binary Field
