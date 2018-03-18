import subprocess
from math import ceil
from os import urandom
from time import sleep
from Crypto.Hash import MD5
from Crypto.Hash import SHA
from Crypto.Hash import HMAC
from Crypto.Cipher import AES

ip = '127.0.0.1'
print "Connecting to "+ip

# pre_master_secret = RSA.encrypt(urandom(48))
# master_secret = PRF(pre_master_secret, "master secret", CR+SR)

#Master Secret is NULL
secret = ""

# Get client and server random from the service and pastes it here.
CR = 'd7aea41011ed779a5420293ae218fe72b27cb309988155dacf3c0c5526cecd35'.decode('hex')
SR = 'd424b7708cb7767d90c322a10ad575ca8cac4f56cc98be1782135f7c2445a400'.decode('hex')

CR = urandom(32)
SR = urandom(32)

MAC_LENGTH = 20
KEY_LENGTH = 32
IV_LENGTH = 16
REQ_BYTES = 2*(MAC_LENGTH + KEY_LENGTH + IV_LENGTH)

sha = SHA.new()
md5 = MD5.new()

def HMAC_hash(secret, key, algo):
	hmac = HMAC.new(secret, key, algo)
	return hmac.digest()

def P_MD5(S1, seed):
	count = int(ceil(1.0*REQ_BYTES/16))
	dp = ['' for i in range(count+1)]
	dp[0] = seed
	for i in range(1,len(dp)):
		dp[i] = HMAC_hash(S1, dp[i-1], md5)
	p_md5 = ''
	for i in range(1,len(dp)):
		p_md5 += HMAC_hash(S1, dp[i]+seed, md5)
	return p_md5

def P_SHA1(S2, seed):
	count = int(ceil(1.0*REQ_BYTES/20))
	dp = ['' for i in range(count+1)]
	dp[0] = seed
	for i in range(1,len(dp)):
		dp[i] = HMAC_hash(S2, dp[i-1], sha)
	p_sha1 = ''
	for i in range(1,len(dp)):
		p_sha1 += HMAC_hash(S2, dp[i]+seed, sha)
	return p_sha1

def PRF(secret, label, seed):
	L_S = len(secret)
	L_S1 = int(ceil(1.0*L_S/2))
	L_S2 = L_S1
	p_md5 = P_MD5(secret[:L_S1], label + seed)
	p_sha1 = P_SHA1(secret[L_S2:], label + seed)
	return ''.join([chr(ord(p_md5[i]) ^ ord(p_sha1[i])) for i in range(REQ_BYTES)])

def pad(s):
	return s+chr(16-len(s)%16)*(16-len(s)%16)

def encrypt(key, mode, iv, plaintext):
	aes = AES.new(key, mode, iv)
	return aes.encrypt(pad(plaintext))

def decrypt(key, mode, iv, ciphertext):
	aes = AES.new(key, mode, iv)
	return aes.decrypt(ciphertext)

label = 'key expansion'
seed = SR+CR

key_block = PRF(secret, label, seed).encode('hex')

Client_MAC = key_block[:MAC_LENGTH*2].decode('hex')
Server_MAC = key_block[MAC_LENGTH*2:MAC_LENGTH*4].decode('hex')
Client_KEY = key_block[MAC_LENGTH*4:MAC_LENGTH*4+KEY_LENGTH*2].decode('hex')
Server_KEY = key_block[MAC_LENGTH*4+KEY_LENGTH*2:MAC_LENGTH*4+KEY_LENGTH*4].decode('hex')
Client_IV = key_block[MAC_LENGTH*4+KEY_LENGTH*4:MAC_LENGTH*4+KEY_LENGTH*4+IV_LENGTH*2].decode('hex')
Server_IV = key_block[MAC_LENGTH*4+KEY_LENGTH*4+IV_LENGTH*2:MAC_LENGTH*4+KEY_LENGTH*4+IV_LENGTH*4].decode('hex')

while(True):
	print "#",
	cmd = raw_input()
	if cmd == "ls" or cmd == "cat flag":
		res = subprocess.check_output(cmd, shell=True)
		enc = encrypt(Server_KEY, AES.MODE_CBC, Server_IV, res)
		print decrypt(Server_KEY, AES.MODE_CBC, Server_IV, enc)
		print enc.encode('hex')
	else:
		res = cmd+": command not found"
		enc = encrypt(Server_KEY, AES.MODE_CBC, Server_IV, res)
		print enc.encode('hex')
	sleep(0.5)
