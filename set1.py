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

def guess_xor_key_by_frequency(hashBits):
	# This is the proposed technique to guess the key by punctuating each possible key by the expected frequency of each letter in the english alphabet
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

def challenge3_guess_xor_key(hash):
	guess = guess_xor_key_by_space(hex_to_bits(hash))
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
		guess = guess_xor_key_by_space(sentenceBits)
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

def bytes_to_ints(bits):
	assert(len(bits)%8 == 0)
	return [bits_to_int(bits[8*i:8*(i+1)]) for i in range(len(bits)//8)]

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

MAX_KEYSIZE = 41

def find_best_keysize_by_hamming_distance(message):
	# This is the proposed way of finding the keysize by taking hamming distance between consecutive blocks of keysize bytes.
	# This works because the expected value of the hamming distance of two chars of a coherent english sentence is less than the expected value of the HD of two "random" characters because in the english alphabet some letters are more frequent than others.
	# It's also important to mention that this works because HD(A^C,B^C) = HD(A,B)
	bestKeysize = -1
	bestHammingDistance = 1000000000000000
	for keysize in range(1,MAX_KEYSIZE):	
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

def find_best_keysize_by_index_of_coincidence(message):
	# This technique finds the best keysize by analyzing the index of coincidence of each keysize.
	# Greater index means more probability of being the correct keysize because the index of a monoalphabetic encryption is greater than the index of a polyalphabetic encrytption,
	# and the correct keysize is the one that makes each block a monoalphabetic enryption (the one that corresponds with that character of the key).
	# That is, the correct keylength l is the one that makes the text containing all the characters at positions with reminder x mod l (for any x) a single-char xor encryption, which character distribution will be similar to the english distribution and not one random (in xor encryptions with longer keys, the distribution of characters tend to be more random and therefore the index of coincidence tends to be lower). More info here https://www.youtube.com/watch?v=-v6AuD6U2lk
	bestKeysize = -1
	bestIndex = -1
	for keysize in range(1,MAX_KEYSIZE):
		l = len(message)
		assert(l%8 == 0)
		l //= 8
		currentIndex = 0
		blocks = [[] for _ in range(keysize)]
		for i in range(l):
			blocks[i%keysize].append(bits_to_int(message[8*i:8*(i+1)]))
		for i in range(keysize):
			lBlock = len(blocks[i])
			counter = [0 for _ in range(256)]
			for n in blocks[i]:
				counter[n] += 1
			for j in range(256):
				currentIndex += (counter[j]/lBlock)**2 # We have to divide by lBlock since we calculate the index of coincidence of the block, not the whole message
		currentIndex /= keysize # We divide to average the indexes of all the blocks
		if currentIndex > bestIndex:
			bestIndex = currentIndex
			bestKeysize = keysize
	return bestKeysize


def challenge6_break_repeating_key_xor():
	with open('s1c6') as f:
	    stringMessage = f.read().replace('\n',"")
	message = base64_to_bits(stringMessage)
	assert(len(message)%8 == 0)
	keysize = find_best_keysize_by_index_of_coincidence(message)
	blocks = [[] for i in range(keysize)]
	for i in range(len(message)//8):
		blocks[i%keysize] += message[8*i:8*(i+1)]
	encryptionKey = []
	for i in range(keysize):
		copy = blocks[i]
		decryption = guess_xor_key_by_space(blocks[i])
		assert(copy == blocks[i])
		encryptionKey += decryption[0]
	return (bits_to_ascii(encryptionKey), bits_to_ascii(apply_repeatedXor(message,encryptionKey)))

expected_s1c6 = ('Terminator X: Bring the noise', "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n")

print("Set 1, Challenge 6:")
print("ok" if challenge6_break_repeating_key_xor() == expected_s1c6 else "--------------FAILED--------------")

###########################################################################################

def bits_to_bytes(bits):
	l = len(bits)
	assert(l%8 == 0)
	bytes = []
	for i in range(l//8):
		bytes.append(bits_to_int(bits[8*i:8*(i+1)]))
	return bytes

def add_round_key(bytes,key):
	assert(len(bytes) == len(key))
	for i in range(16):
		bytes[i] ^= key[i]

lookupTable = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,   0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
inverseLookupTable = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

def sub_bytes(bytes, inv):
    for i in range(len(bytes)):
        bytes[i] = lookupTable[bytes[i]] if inv == 1 else inverseLookupTable[bytes[i]]
    return bytes

test = [0,1,2,254,255]
sub_bytes(test,1)
assert(test == [99, 124, 119, 187, 22])
test = [0,1,2,254,255]
sub_bytes(test,-1)
assert(test == [82, 9, 106, 12, 125])

def shift_rows(bytes,inv):
	assert(inv == 1 or inv == -1) # this tells us if we want to encrypt or decrypt
	newBytes = [0 for _ in range(16)]
	for r in range(1,4):
		for i in range(4):
			newBytes[(4*i+r -4*r*inv +16)%16] = bytes[4*i+r]

mixCol = [
	[2,3,1,1],
	[1,2,3,1],
	[1,1,2,3],
	[3,1,1,2]
]

invMixCol = [
	[14,11,13,9],
	[9,14,11,13],
	[13,9,14,11],
	[11,13,9,14]
]

def fieldMult(a,b): # Reemplazar esto por la mult del cuerpo
	
	return a*b

def mix_columns(bytes,inv):
	newBytes = []
	for i in range(4):
		col = [0,0,0,0]
		for j in range(4):
			for k in range(4):
				col[j] ^= fieldMult(mixCol[j][k] if inv == 1 else invMixCol[j][k],bytes[4*i+k])
		newBytes += col
	bytes = newBytes
	return newBytes

def challenge7_decrypt_message(key):
	with open('s1c7') as f:
	    stringMessage = f.read().replace('\n',"")
	message = bits_to_bytes(base64_to_bits(stringMessage))
	k = bits_to_bytes(string_to_bits(key))
	return k


print("Set 1, Challenge 7:")
# print(challenge7_decrypt_message("YELLOW SUBMARINE"))
# print("ok" if challenge7_decrypt_message("YELLOW SUBMARINE") == expected_s1c7 else "--------------FAILED--------------")

# Note: you can decrypt the message with the following command line
# openssl aes-128-ecb -d -a -in s1c7 -K  $(echo -n "YELLOW SUBMARINE" | hexdump -v -e '/1 "%02X"')
# or
# openssl aes-128-ecb -d -a -K 59454c4c4f57205355424d4152494e45 -in s1c7
# (59454c4c4f57205355424d4152494e45 is the hex encoding for "YELLOW SUBMARINE")

# Here's an example implementation: https://github.com/halloweeks/AES-128-ECB/tree/main








###########################################################################################

# if challenge 8 becomes too hard, here's a help: https://wgallagher86.medium.com/aes-128-ecb-mode-in-go-75bd59b74541