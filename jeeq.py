#!/usr/bin/python3

# jeeq 0.0.5
# https://github.com/rutrus/jeeq
# Licensed under GPLv3

import random
import base64
import hashlib
import sys
import platform

_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_r  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_b  = 0x0000000000000000000000000000000000000000000000000000000000000007
_a  = 0x0000000000000000000000000000000000000000000000000000000000000000
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

jeeqversion='0.0.5'

def str_to_long(b):
	res = 0
	pos = 1
	for a in reversed(b):
		res += int(a) * pos
		pos *= 256
	return res

def decode_hex(n):
	n = str(n)
	if len(n) % 2: n += '0'
	return bytearray.fromhex(n)

def encode_hex(n):
	n = bytearray(n)
	return n.hex()

class CurveFp( object ):
	def __init__( self, p, a, b ):
		self.__p = p
		self.__a = a
		self.__b = b

	def p( self ):
		return self.__p

	def a( self ):
		return self.__a

	def b( self ):
		return self.__b

	def contains_point( self, x, y ):
		return ( y * y - ( x * x * x + self.__a * x + self.__b ) ) % self.__p == 0

class Point( object ):
	def __init__( self, curve, x, y, order = None ):
		self.__curve = curve
		self.__x = x
		self.__y = y
		self.__order = order
		if self.__curve: assert self.__curve.contains_point( x, y )
		if order: assert self * order == INFINITY

	def __add__( self, other ):
		if other == INFINITY: return self
		if self == INFINITY: return other
		assert self.__curve == other.__curve
		p = self.__curve.p()
		if self.__x == other.__x:
			if ( self.__y + other.__y ) % p == 0:
				return INFINITY
			else:
				return self.double()

		l = ( ( other.__y - self.__y ) * \
			inverse_mod( other.__x - self.__x, p ) ) % p
		x3 = ( l * l - self.__x - other.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def __mul__( self, other ):
		def leftmost_bit( x ):
			assert x > 0
			result = 1
			while result <= x: result = 2 * result
			return result // 2

		e = other
		if self.__order: e = e % self.__order
		if e == 0: return INFINITY
		if self == INFINITY: return INFINITY
		assert e > 0
		e3 = 3 * e
		negative_self = Point( self.__curve, self.__x, -self.__y, self.__order )
		i = leftmost_bit( e3 ) // 2
		result = self
		while i > 1:
			result = result.double()
			if ( e3 & i ) != 0 and ( e & i ) == 0: result = result + self
			if ( e3 & i ) == 0 and ( e & i ) != 0: result = result + negative_self
			i = i // 2
		return result

	def negative_self(self):
		return Point( self.__curve, self.__x, -self.__y, self.__order )

	def __rmul__( self, other ):
		return self * other

	def __str__( self ):
		if self == INFINITY: return "infinity"
		return "({},{})".format( self.__x, self.__y )

	def double( self ):
		if self == INFINITY:
			return INFINITY

		p = self.__curve.p()
		a = self.__curve.a()
		l = ( ( 3 * self.__x * self.__x + a ) * \
					inverse_mod( 2 * self.__y, p ) ) % p
		x3 = ( l * l - 2 * self.__x ) % p
		y3 = ( l * ( self.__x - x3 ) - self.__y ) % p
		return Point( self.__curve, x3, y3 )

	def x( self ):
		return self.__x

	def y( self ):
		return self.__y

	def curve( self ):
		return self.__curve
	
	def order( self ):
		return self.__order

	def ser( self, comp = True ):
		if comp:
			return decode_hex( ('%02x' % (2 + (self.__y & 1))) + ('%064x' % self.__x))
		return decode_hex( '04' + ('%064x' % self.__x) + ('%064x' % self.__y) )
		
INFINITY = Point( None, None, None )
curveBitcoin = CurveFp(_p, _a, _b)
generatorBitcoin = Point(curveBitcoin, _Gx, _Gy, _r)

def inverse_mod( a, m ):
	if a < 0 or m <= a: a = a % m
	c, d = a, m
	uc, vc, ud, vd = 1, 0, 0, 1
	while c != 0:
		q, c, d = divmod( d, c ) + ( c, )
		uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
	assert d == 1
	if ud > 0: return ud
	else: return ud + m

def hash_160(public_key):
	md = hashlib.new('ripemd160')
	md.update(hashlib.sha256(public_key).digest())
	return md.digest()

def public_key_to_bc_address(public_key, addrtype = 0):
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160, addrtype)

def hash_160_to_bc_address(h160, addrtype = 0):
	vh160 = decode_hex(addrtype) + h160
	h = Hash(vh160)
	addr = vh160 + h[0:4]
	return b58encode(encode_hex(addr))

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
	"""
	encode v, which is a string of bytes, to base58.		
	"""
	long_value = 0
	for (i, c) in enumerate(v[::-1]):
		long_value += (256**i) * ord(c)

	result = ''
	while long_value >= __b58base:
		div, mod = divmod(long_value, __b58base)
		result = __b58chars[mod] + result
		long_value = div
	result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression:
	# leading 0-bytes in the input become leading-1s
	nPad = 0
	for c in v:
		if c == '\0': nPad += 1
		else: break
	return (__b58chars[0]*nPad) + result

def b58decode(v, length = None):
	"""
	decode v into a string of len bytes
	"""
	long_value = 0
	for (i, c) in enumerate(v[::-1]):
		long_value += __b58chars.find(c) * (__b58base**i)

	result = ''
	while long_value >= 256:
		div, mod = divmod(long_value, 256)
		result = chr(mod) + result
		long_value = div
	result = chr(long_value) + result

	nPad = 0
	for c in v:
		if c == __b58chars[0]: nPad += 1
		else: break

	result = chr(0)*nPad + result
	if length is not None and len(result) != length:
		return None
	return result

def Hash(data):
	# Double hash
	return sha256(sha256(data))

def EncodeBase58Check(vchIn):
	hash = Hash(vchIn)
	return b58encode(vchIn + hash[0:4])

def DecodeBase58Check(psz):
	vchRet = b58decode(psz, None)
	key = vchRet[0:-4]
	csum = vchRet[-4:]
	hash = Hash(key)
	cs32 = hash[0:4]
	if cs32 != csum:
		return None
	else:
		return key

def sha256(a):
	if type(a) == str: a = bytes(a, 'utf8')
	return hashlib.sha256(a).digest()

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def ECC_YfromX(x, curved = curveBitcoin, odd=True):
	_p = curved.p()
	_a = curved.a()
	_b = curved.b()
	for offset in range(128):
		Mx = x + offset
		My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
		My = pow(My2, (_p+1)//4, _p )

		if curved.contains_point(Mx,My):
			if odd == bool(My&1):
				return [My,offset]
			return [_p-My,offset]
	raise Exception('ECC_YfromX: No Y found')

def private_header(msg, v):
	assert v < 1, "Can't write version %d private header" % v
	r = b''
	if v == 0:
		r += decode_hex('%08x' % len(msg))
		r += sha256(msg)[:2]
	return decode_hex('%02x' % v) + decode_hex('%04x' % len(r)) + r

def public_header(pubkey, v):
	assert v < 1, "Can't write version %d public header" % v
	r = b''
	if v == 0:
		r = sha256(pubkey)[:2]
	return b'\x6a\x6a' + decode_hex('%02x' % v) + decode_hex('%04x' % len(r)) + r

def encrypt_message(pubkey, m, curved = curveBitcoin, generator = generatorBitcoin):
	r = b''
	msg = private_header(m, 0) + bytes(m,'utf8')
	msg = msg + bytes( 32-(len(msg) % 32) )
	msgs = chunks(msg, 32)
	_r = generator.order()

	P = generator
	if len(pubkey) == 33: #compressed
		print(pubkey[1:33])
		pk = Point( curved, str_to_long(pubkey[1:33]), ECC_YfromX(str_to_long(pubkey[1:33]), curved, pubkey[0] == b'\x03')[0], _r )
	else:
		assert len(pubkey) == 65, "Wrong public Key"
		pk = Point( curved, str_to_long(pubkey[1:33]), str_to_long(pubkey[33:65]), _r )

	for i in range(len(msgs)):
		rand = decode_hex( '%013x' % int(random.random() * 0xfffffffffffff) * 5)
		n = str_to_long(rand) >> 4
		Mx = str_to_long(msgs[i])
		My,xoffset = ECC_YfromX(Mx, curved)
		M = Point( curved, Mx+xoffset, My, _r )

		T = P * n
		U = pk * n + M

		toadd = T.ser() + U.ser()
		toadd = bytearray(chr(toadd[0] - 2 + 2 * xoffset),'utf8') + toadd[1:]
		r += toadd
	return base64.b64encode(public_header(pubkey,0) + r)

def pointSerToPoint(Aser, curved = curveBitcoin, generator = generatorBitcoin):
	_r  = generator.order()
	assert bytes(chr(Aser[0]),'utf8') in [b'\x02',b'\x03',b'\x04']
	if bytes(chr(Aser[0]),'utf8') == b'\x04':
		return Point( curved, str_to_long(Aser[1:33]), str_to_long(Aser[33:]), _r )
	Mx = str_to_long(Aser[1:])
	return Point( curved, Mx, ECC_YfromX(Mx, curved, bytes(chr(Aser[0]),'utf8') == b'\x03')[0], _r )

def decrypt_message(pvk, enc, curved = curveBitcoin, verbose = False, generator = generatorBitcoin):
	pvk = str_to_long(pvk)
	P = generator * pvk
	pubkeys = [(P.ser(True)), (P.ser(False))]
	enc = base64.b64decode(enc)

	assert enc[:2] == b'\x6a\x6a'
	phv = enc[2]
	assert phv == 0, "Can't read version %d public header" % phv
	hs = str_to_long(enc[3:5])
	public_header = enc[5:5+hs]
	if verbose: print ('Public header (size:%d)%s%s' % (hs, ': 0x' * int(bool(hs>0)), encode_hex(public_header)))
	if verbose: print ('  Version: %d' % phv)
	checksum_pubkey = public_header[:2]
	if verbose: print ('  Checksum of pubkey: %s' % encode_hex(checksum_pubkey))
	address = list(filter(lambda x:sha256(x)[:2] == checksum_pubkey, pubkeys))
	assert len(address) > 0, 'Bad private key'
	address = address[0]
	enc = enc[5+hs:]

	r = b''
	for Tser,User in map(lambda x:[x[:33],x[33:]], chunks(enc, 66)):
		ots = Tser[0]
		xoffset = ots >> 1
		Tser = bytearray(chr(2 + (ots & 1)),'utf8') + Tser[1:]
		T = pointSerToPoint(Tser, curved, generator)
		U = pointSerToPoint(User, curved, generator)

		V = T * pvk
		Mcalc = U + V.negative_self()
		r += decode_hex('%064x'%(Mcalc.x()-xoffset))
	pvhv = r[0]
	assert pvhv == 0, "Can't read version %d private header" % pvhv
	phs = str_to_long(r[1:3])
	private_header = r[3:3+phs]
	if verbose: print ('Private header (size:%d): 0x%s' % (phs, encode_hex(private_header)))
	size = str_to_long(private_header[:4])
	checksum = private_header[4:6]
	if verbose: print ('  Message size: %d' % size)
	if verbose: print ('  Checksum: %04x' % str_to_long(checksum))
	r = r[3+phs:]

	msg = r[:size]
	hashmsg = sha256(msg)[:2]
	checksumok = hashmsg == checksum
	if verbose: print ('Decrypted message: ' + str(msg))
	if verbose: print ('  Hash: ' + encode_hex(hashmsg))
	if verbose: print ('  Corresponds: ' + str(checksumok))

	return [msg, checksumok, address]

def KeyboardInterruptText():
	if platform.system() == "Windows":
		return "Hit Ctrl-C or Ctrl-Z"
	return "Hit Ctrl-D"

def GetArg(a, d = ''):
	for i in range(1, len(sys.argv)):
		if sys.argv[i-1] == a:
			if a in ['-i']:
				f = open(sys.argv[i],'r')
				content=f.read()
				f.close()
				return content
			return sys.argv[i]
	if a == '-i':
		print ("Type the text to use. " + KeyboardInterruptText() + " to stop writing: ")
		return ''.join(sys.stdin.readlines())
	if a == '-k':
		return raw_input("\nType the key to use: ")
	return d

def GetFlag(a, d = ''):
	for i in range(1,len(sys.argv)):
		if sys.argv[i] == a:
			return True
	return False

def print_help(e = False):
	print ('jeeq.py ' + jeeqversion)
	print ('Encryption/decryption tool using Bitcoin keys')
	print ('usage:')
	print ('   KEY GENERATION: ' + sys.argv[0] + ' -g [-v network number]')
	print ('   ENCRYPTION:     ' + sys.argv[0] + ' -e -i input_file -o output_file -k public_key  [-v network number]')
	print ('   DECRYPTION:     ' + sys.argv[0] + ' -d -i input_file -o output_file -k private_key [-v network number]\n')
	print ('Missing arguments will be prompted.')
	print ('Public keys are NOT Bitcoin addresses, you NEED public keys.')
	if e: exit(0)

def generate_keys(curved = curveBitcoin, bitcoin = True, addv = 0, G = generatorBitcoin):  #will return private key < 2^256
	# WARNING!! RANDOM GENERATOR IS NOT SAFE!!
	_r  = G.order()
	rand = ( '%013x' % int(random.random() * 0xfffffffffffff) ) * 5
	pvk  = (int(rand, 16) >> 4) % _r
	P = pvk * G
	btcaddresses=[]
	if bitcoin:
		btcaddresses.append(public_key_to_bc_address(P.ser(True), addv))
		btcaddresses.append(public_key_to_bc_address(P.ser(False), addv))
	return ['%064x' % pvk, encode_hex(P.ser(True)), encode_hex(P.ser(False)), btcaddresses]

if __name__ == '__main__':
	"""
	Usage:
	encrypted = encrypt_message(pubkey, "hello world!", generatorBitcoin)
	output    = decrypt_message(pvk, base64d_msg, verbose=True, generatorBitcoin)
	"""
	if GetFlag('--help') or GetFlag('-h'):
		print_help(True)

	if GetFlag('--generate-keys') or GetFlag('-g'):
		v = int(GetArg('-v', 0))
		keys = generate_keys(addv = v)
		print ('Private key:              ', keys[0])
		print ('Compressed public key:    ', keys[1])
		print ('Uncompressed public key:  ', keys[2])
		print ('Compressed address:       ', keys[3][0])
		print ('Uncompressed address:     ', keys[3][1])
		exit(0)

	if GetFlag('-e'):
		addv = int(GetArg('-v', 0))
		message = GetArg('-i')
		public_key = GetArg('-k')

		if len(public_key) in [66,130]:
			public_key = decode_hex(public_key)
		assert len(public_key) in [33,65], 'Bad public key'

		output = encrypt_message(public_key, message, generator = generatorBitcoin)

		output_file = GetArg('-o')
		if output_file:
			f = open(output_file,'wb')
			f.write(output)
			f.close()
		print ("\n\nEncrypted message to " + public_key_to_bc_address(public_key,addv) + ":\n" + str(output))
	elif GetFlag('-d'):
		addv = int(GetArg('-v', 0))
		message = GetArg('-i')
		private_key = GetArg('-k')

		if len(private_key) == 64:
			private_key = decode_hex(private_key)
		assert len(private_key) == 32, 'Bad private key, you must give it in hexadecimal'

		output = decrypt_message(private_key, message, verbose = True, generator = generatorBitcoin)

		output_file = GetArg('-o')
		if output_file:
			f = open(output_file,'wb')
			f.write(output[0])
			f.close()
		print ("\nDecrypted message to " + public_key_to_bc_address(output[2], addv) + ":\n" + str(output[0]))
	else:
		print_help(True)
