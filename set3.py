from set2 import *

def pick_message():
	with open('s3c17') as f:
	    messages = [mes.replace('\n','') for mes in f.readlines()]
	index = randint(0,9)
	message = bits_to_ascii(base64_to_bits(messages[index]))
	randomIv = "".join([chr(randint(0,255)) for _ in range(16)])
	return (
		aes128(pad_message(message), randomKey, 1, False, randomIv),
		randomIv
	)

def has_padding(string):
	l = len(string)
	if not l:
		return False
	c = ord(string[l-1])
	if string[-c:l] == chr(c)*c:
		return True
	return False


def check_correct_padding(encryptedMessage):
	ciphertext = encryptedMessage[0]
	iv = encryptedMessage[1]
	message = aes128(ciphertext, randomKey, -1, False, iv)
	return has_padding(message)

if TEST:
	assert(has_padding("afhjkdshgkajhdfs\x01"))
	assert(not has_padding("afhjkdshgkajhdfs\x02"))
	assert(has_padding("afhjkdshgkajhdfs\x02\x02"))
	assert(not has_padding("afhjkdshgkajhdfs\x03\x02"))
	assert(not has_padding("afhjkdshgkajhdfs"))
	assert(not has_padding(""))

	testIv = "".join([chr(randint(0,255)) for _ in range(16)])
	testMessage = pad_message("01234")
	encryptedTest = aes128(testMessage, randomKey, 1, False, testIv)
	assert(check_correct_padding((encryptedTest, testIv)))
	testMessage = "0"*15 + chr(10)
	encryptedTest = aes128(testMessage, randomKey, 1, False, testIv)
	assert(not check_correct_padding((encryptedTest, testIv)))

def decrypt_block_with_padding_attack(block, iv):
	decryptedBlock = ""
	for i in range(16):
		ivSuffix = "".join([chr((i+1) ^ ord(decryptedBlock[j]) ^ ord(iv[16-i+j])) for j in range(i)])
		for c in range(256):
			if check_correct_padding((block, iv[0:15-i] + chr(c) + ivSuffix)):
				newChar = chr(c ^ (i+1) ^ ord(iv[15-i]))
				decryptedBlock = newChar + decryptedBlock
				break
		assert(len(decryptedBlock) == i+1)
	return decryptedBlock

def challenge17():
	pair = pick_message()
	decryptedMessage = ""
	previousBlock = pair[1]
	ciphertext = pair[0]
	for i in range(len(ciphertext)//16):
		decryptedMessage += decrypt_block_with_padding_attack(ciphertext[16*i:16*(i+1)],previousBlock)
		print(i+1, repr(decryptedMessage))
		previousBlock = ciphertext[16*i:16*(i+1)]
	return decryptedMessage

if TEST:
	print("Set 3, Challenge 17:")
	print("ok" if challenge17() else "--------------FAILED--------------")

#################################################################################################