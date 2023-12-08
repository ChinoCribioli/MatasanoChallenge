oa = ord('a')
oz = ord('z')
oA = ord('A')
oZ = ord('Z')
o0 = ord('0')
o9 = ord('9')

def int_to_bits(n, size = 8): # the size parameter is to fill with leading zeroes if necessary
	bits = []
	while n > 0 :
		bits.append(1 if n % 2 else 0)
		n //= 2
	while len(bits) < size :
		bits.append(0)
	return bits[::-1] # this is to reverse the string

def bits_to_int(bits):
	integer = 0
	for c in bits:
		integer *= 2
		integer += c
	return integer

def hexChar_to_bits(char):
	index = ord(char)
	if o0 <= index and index <= o9:
		return int_to_bits(index-o0,4)
	else:
		return int_to_bits(index-oa+10,4)

def hex_to_bits(hash):
	bits = []
	for c in hash:
		bits += hexChar_to_bits(c)
	return bits

def sixBits_to_base64(string):
	index = bits_to_int(string)
	if index < 26:
		return chr(index+oA)
	index -= 26
	if index < 26:
		return chr(index+oa)
	index -= 26
	if index < 10:
		return chr(index+o0)
	index -= 10
	if index < 1:
		return '+'
	else :
		return '/'

def bits_to_base64(bits):
	answer = ""
	for i in range(0,len(bits)//6):
		answer += sixBits_to_base64(bits[6*i:6*(i+1)])
	return answer

def challenge1_hex_to_base64(hash):
	bits = hex_to_bits(hash)
	return bits_to_base64(bits)

print("Set 1, Challenge 1:")
ans = challenge1_hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
print("ok" if ans == expected else "--------------FAILED--------------")

#############################################################

def fourBits_to_hex(bits):
	integer = bits_to_int(bits)
	if integer < 10 :
		return str(integer)
	else : 
		return chr(oa+integer-10)

def bits_to_hex(bits):
	answer = ""
	for i in range(0,len(bits)//4):
		answer += fourBits_to_hex(bits[4*i:4*(i+1)])
	return answer
	
def challenge2_fixed_XOR(hash1,hash2):
	bits1 = hex_to_bits(hash1)
	bits2 = hex_to_bits(hash2)
	finalBits = [bits1[i]^bits2[i] for i in range(len(bits1))]
	return bits_to_hex(finalBits)

print("Set 1, Challenge 2:")
ans = challenge2_fixed_XOR("1c0111001f010100061a024b53535009181c","686974207468652062756c6c277320657965")
expected = "746865206b696420646f6e277420706c6179"
print("ok" if ans == expected else "--------------FAILED--------------")

###############################################################

def bits_to_ascii(bits):
	assert(len(bits)%8 == 0)
	answer = ""
	for i in range(0,len(bits)//8):
		answer += chr(bits_to_int(bits[8*i:8*(i+1)]))
	return answer

def apply_xor_to_char(c, key):
	cBits = hexChar_to_bits(c)
	keyBits = hexChar_to_bits(key)
	result = [cBits[i]^keyBits[i] for i in range(len(cBits))]
	return bits_to_hex(result)

def apply_repeatedXor(bits, key): # key must be an array of bits
	response = [0 for _ in range(len(bits))]
	keyLength = len(key)
	for i in range(len(bits)):
		response[i] = bits[i] ^ key[i%keyLength]
	return response

def is_legal_ascii(index):
	return index <= 126 and not (index in range(12,32))

letterFrequency = {
	'E' : 12.0,
	'T' : 9.10,
	'A' : 8.12,
	'O' : 7.68,
	'I' : 7.31,
	'N' : 6.95,
	'S' : 6.28,
	'R' : 6.02,
	'H' : 5.92,
	'D' : 4.32,
	'L' : 3.98,
	'U' : 2.88,
	'C' : 2.71,
	'M' : 2.61,
	'F' : 2.30,
	'Y' : 2.11,
	'W' : 2.09,
	'G' : 2.03,
	'P' : 1.82,
	'B' : 1.49,
	'V' : 1.11,
	'K' : 0.69,
	'X' : 0.17,
	'Q' : 0.11,
	'J' : 0.10,
	'Z' : 0.07,
	' ' : 20.0 # I make the guess that 20% of the characters of valid sentences are spaces
}

for key, value in letterFrequency.items():
	letterFrequency[key] /= 100

def letter_frequency_metric(bits):
	appearances = {' ' : 0}
	for c in range(oA,oZ+1):
		appearances[chr(c)] = 0
	penalty = 0.0 # non-letter characters
	l = len(bits)
	assert(l%8 == 0)
	for i in range(0,l//8):
		index = bits_to_int(bits[8*i:8*(i+1)])
		if not is_legal_ascii(index):
			return 1000*l
		if index in range(oa,oz+1):
			appearances[chr(index-oa+oA)] += 1/l
		elif index in range(oA,oZ+1):
			appearances[chr(index)] += 1/l
		elif index == 32: # c == ' '
			appearances[chr(index)] += 1/l
		elif index in range(o0,o9+1):
			# continue
			penalty += 1/(l)
		else:
			penalty += 20/l # I penalize every character that is neither a letter, a number or a space
	for key, value in letterFrequency.items():
		penalty += abs(value-appearances[key])#**2
	return penalty

def guess_xor_key(hashBits):
	bestPenalty = 10000000000000
	bestKey = []
	for i in range(256):
		key = int_to_bits(i)
		guess = apply_repeatedXor(hashBits,key)
		guessPenalty = letter_frequency_metric(guess)
		if guessPenalty < bestPenalty:
			bestPenalty = guessPenalty
			bestKey = key
	return (bestKey, apply_repeatedXor(hashBits,bestKey))

def challenge3_guess_xor_key(hash):
	guess = guess_xor_key(hex_to_bits(hash))
	return (bits_to_int(guess[0]),bits_to_ascii(guess[1]))


print("Set 1, Challenge 3:")
print("ok" if challenge3_guess_xor_key("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736") == (88, "Cooking MC's like a pound of bacon") else "--------------FAILED--------------")

#########################################################################################

def string_to_bits(string):
	bits = []
	for c in string:
		bits += int_to_bits(ord(c),8)
	return bits

def challenge4_find_message():
	with open('s1c4') as f:
	    sentences = f.readlines()
	for i in range(len(sentences)):
		sentences[i] = sentences[i].replace("\n","") # Erase the trailing line break
	bestPenalty = 10000000000000
	bestIndex = -1
	bestKey = ''
	for i in range(len(sentences)):
		sentenceBits = hex_to_bits(sentences[i])
		guess = guess_xor_key(sentenceBits)
		penalty = letter_frequency_metric(guess[1])
		if penalty < bestPenalty:
			bestPenalty = penalty
			bestIndex = i
			bestKey = guess[0]
	return (bestIndex, bits_to_int(bestKey), bits_to_ascii(apply_repeatedXor(hex_to_bits(sentences[bestIndex]),bestKey)))
	
print("Set 1, Challenge 4:")
print("ok" if challenge4_find_message() == (170, 53, 'Now that the party is jumping\n') else "--------------FAILED--------------")

############################################################################################

def challenge5_encrypt_with_repeating_key_xor(message,key):
	return bits_to_hex(apply_repeatedXor(string_to_bits(message),string_to_bits(key)))

print("Set 1, Challenge 5:")
print("ok" if challenge5_encrypt_with_repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal","ICE")
	== "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" else "--------------FAILED--------------")

###########################################################################################

def base64Char_to_int(char):
	if char == '+':
		return 62
	if char == '/':
		return 63
	index = ord(char)
	if index in range(oA,oZ+1):
		return index-oA
	if index in range(oa,oz+1):
		return index-oa+26
	if index in range(o0,o9+1):
		return index-o0+52

def base64Char_to_bits(char):
	return int_to_bits(base64Char_to_int(char),6)

def base64_to_bits(string):
	bits = []
	for c in string:
		if c == '\n':
			continue
		if c == '=':
			break
		assert(c == bits_to_base64(base64Char_to_bits(c)))
		bits += base64Char_to_bits(c)
	if string[-2:len(string)] == "==":
		for i in range(1,5):
			assert(bits[-i] == 0)
		bits = bits[0:-4]
	elif string[-1:len(string)] == "=":
		for i in range(1,3):
			assert(bits[-i] == 0)
		bits = bits[0:-2]
	return bits

def hamming_distance_bits(bits1,bits2):
	counter = 0
	l1 = len(bits1)
	l2 = len(bits2)
	for i in range(min(l1,l2)):
		counter += int(bits1[i] != bits2[i])
	return counter+max(l1,l2)-min(l1,l2)

def hamming_distance_strings(string1,string2):
	return hamming_distance_bits(string_to_bits(string1),string_to_bits(string2))

assert(hamming_distance_strings("this is a test","wokka wokka!!!") == 37)

def find_best_keysize(message):
	bestKeysize = -1
	bestHammingDistance = 1000000000000000
	for keysize in range(1,41): # tiene sentido probar con 1?
		currentDistance = 0
		# len(message)//8 is the number of bytes, len(message)//(8*keysize) is the number of disjoint blocks of keysize bytes
		for i in range(1,len(message)//(8*keysize)):
			currentDistance += hamming_distance_bits(message[(i-1)*8*keysize:(i)*8*keysize],message[(i)*8*keysize:(i+1)*8*keysize])/keysize
		currentDistance /= len(message)//(8*keysize)-1 # Since we calculated several normalized-hamming-distances, we want to average them since the numeber of comparisons vary between different keysizes
		if currentDistance < bestHammingDistance:
			bestHammingDistance = currentDistance
			bestKeysize = keysize
	return bestKeysize
	# This is a way of finding the keysize that is not very effective but a bit curious. It states that the keysize is equal to the gcd of the all the differences of position of equal bytes.
	# The logic behind this is that if we have two equal bytes, it its probable that they are equal because they were the same letter before the encryption AND they are in positions with the same remainder modulo keysize.
	# This is not very reliable when the message is long because having a colission of type A^B = C^D breaks the logic
	'''
	import math
	positions = [[] for _ in range(256)]
	for i in range(len(message)//8):
		n = bits_to_int(message[8*i:8*(i+1)])
		positions[n].append(i)
	keysize = 0
	for n in range(256):
		if len(positions[n]) < 2:
			continue
		differences = [positions[n][i]-positions[n][i-1] for i in range(1,len(positions[n]))]
		for dif in differences:
			keysize = math.gcd(keysize,dif)
	return keysize
	'''

def guess_xor_key_by_space(message):
	# This technique tries to find the key of a message by assuming that the most common character in a message is a space
	counter = [0 for i in range(256)]
	for i in range(len(message)//8):
		counter[bits_to_int(message[8*i:8*(i+1)])] += 1
	moreCommonChar = -1
	appearances = -1
	for i in range(256):
		if appearances < counter[i]:
			appearances = counter[i]
			moreCommonChar = i
	key = int_to_bits(moreCommonChar ^ ord(' '))
	return (key,apply_repeatedXor(message,key))

def bytes_to_ints(bits):
	assert(len(bits)%8 == 0)
	return [bits_to_int(bits[8*i:8*(i+1)]) for i in range(len(bits)//8)]

def challenge6_break_repeating_key_xor():
	with open('s1c6') as f:
	    stringMessage = f.read().replace('\n',"")
	message = base64_to_bits(stringMessage)
	assert(len(message)%8 == 0)
	keysize = find_best_keysize(message)
	blocks = [[] for i in range(keysize)]
	for i in range(len(message)//8):
		blocks[i%keysize] += message[8*i:8*(i+1)]
	encryptionKey = []
	for i in range(keysize):
		copy = blocks[i]
		# decryption = guess_xor_key(blocks[i])
		decryption = guess_xor_key_by_space(blocks[i])
		assert(copy == blocks[i])
		encryptionKey += decryption[0]
	# print("the encryptionKey is:", bits_to_ascii(encryptionKey), f"({len(bits_to_ascii(encryptionKey))})")
	return bits_to_ascii(apply_repeatedXor(message,encryptionKey))

print("Set 1, Challenge 6:")
print("the result of the challenge is:")
print(challenge6_break_repeating_key_xor())