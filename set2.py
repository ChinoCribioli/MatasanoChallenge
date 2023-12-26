from set1 import *

def challenge9_pad_block(block, desiredLength, asString = True): # asString is True when the parameters as passed as string and False when passed as lists
	assert(len(block) <= desiredLength)
	padding = desiredLength - len(block)
	if asString:
		c = chr(padding)
	else:
		c = [padding]
	return block + c*padding

if TEST:
	print("Set 2, Challenge 9:")
	ans = challenge9_pad_block("YELLOW SUBMARINE",20)
	expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
	print("ok" if ans == expected else "--------------FAILED--------------")

#################################################################################################

def challenge10_decrypt_cbc(key,ivString):
	with open('s2c10') as f:
	    stringMessage = f.read().replace('\n',"")
	message = bits_to_ascii(base64_to_bits(stringMessage))
	return aes128(message,key,-1,False,ivString)

if TEST:
	print("Set 2, Challenge 10:")
	expected_s2c10 = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
	print("ok" if challenge10_decrypt_cbc("YELLOW SUBMARINE",chr(0)*16) == expected_s2c10 else "--------------FAILED--------------")

#################################################################################################

def pad_message(message):
	r = 16-(len(message)%16)
	r = 0 if r == 16 else r
	return challenge9_pad_block(message,len(message)+r)

from random import randint

def random_encrypt_ecb(message):
	key = "".join([chr(randint(0,255)) for _ in range(16)])
	message = "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) + message # add 5 to 10 random bytes at the beginning
	message += "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) # append 5 to 10 random bytes at the end
	message = pad_message(message)
	return aes128(message,key,1)

def random_encrypt_cbc(message):
	key = "".join([chr(randint(0,255)) for _ in range(16)])
	iv = [chr(randint(0,255)) for _ in range(16)]
	message = "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) + message # add 5 to 10 random bytes at the beginning
	message += "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) # append 5 to 10 random bytes at the end
	message = pad_message(message)
	return aes128(message,key,1, False, iv)

def guess_encryption_type(fun):
	cipherText = fun("X"*48)
	cipherBytes = bits_to_bytes(string_to_bits(cipherText))
	if has_repeating_blocks(cipherBytes):
		return "ECB"
	return "CBC"

randomEncryptionModes = [random_encrypt_ecb, random_encrypt_cbc]

def challenge11_guess_black_box(numberOfExperiments):
	for _ in range(numberOfExperiments):
		mode = randint(0,1)
		guess = guess_encryption_type(randomEncryptionModes[mode])
		assert(guess == ("CBC" if mode else "ECB"))

if TEST:
	print("Set 2, Challenge 11:")
	challenge11_guess_black_box(100)
	print("ok")

#################################################################################################

randomKey = "".join([chr(randint(0,255)) for _ in range(16)])
givenText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
givenText = bits_to_ascii(base64_to_bits(givenText))

def targetEncryptionFunction(message):
	paddedMessage = pad_message(message + givenText)
	return aes128(paddedMessage,randomKey,1)

def find_size_of_cipher(fun):
	initialLen = len(fun(""))
	for i in range(17):
		currentLen = len(fun("0"*i))
		if currentLen > initialLen:
			return initialLen - (i-1)

def challenge12_find_unknown_string():
	assert(find_size_of_cipher(targetEncryptionFunction) == len(givenText))
	assert(guess_encryption_type(targetEncryptionFunction) == "ECB")
	cipherLen = find_size_of_cipher(targetEncryptionFunction)
	recoveredBytes = []
	recoveredText = ""
	for i in range(cipherLen): # this part complies the following invariant: "we already recovered the first i characters of the givenText"
		print(f"step {i}")
		assert(i == len(recoveredBytes))
		blockReminder = (-1-i)%16
		baitBlock = "A" * blockReminder # Now, baitBlock will have a length such that the baitBlock + the already recovered text is congruent to -1 modulo 16, so we will be able to peel the next character of the givenText analyzing the last block of this part of the message
		relB = (len(baitBlock)+i)//16 # relB stands for relevantBlock: this is the block we have to look to compare the bait with the actual givenText
		baitResult = targetEncryptionFunction(baitBlock)[16*relB:16*(relB+1)]
		for c in range(256):
			if targetEncryptionFunction(baitBlock + recoveredText + chr(c))[16*relB:16*(relB+1)] == baitResult:
				recoveredBytes.append(c)
				recoveredText = bytes_to_string(recoveredBytes)
				print(recoveredText)
				break
	return recoveredText

if TEST:
	print("Set 2, Challenge 12:")
	expected_s2c12 = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
	print("ok" if challenge12_find_unknown_string() == expected_s2c12 else "--------------FAILED--------------")

#################################################################################################

def parse_profile(encondedUser):
	parameters = encondedUser.split('&')
	user = {}
	for parameter in parameters:
		p = parameter.split('=')
		user[p[0]] = p[1]
	return user

assert(parse_profile("foo=bar&baz=qux&zap=zazzle") == { 'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle' })

def encode_user(user):
	vectorizedUser = []
	for key, value in user.items():
		vectorizedUser.append(f"{key}={value}")
	return "&".join(vectorizedUser)

assert(encode_user({ 'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle' }) == "foo=bar&baz=qux&zap=zazzle")

idCounter = 0

def unencrypted_profile_for(email):
	sanitizedEmail = email.replace('&','').replace('=','')
	user = {'email': sanitizedEmail}
	global idCounter
	user['uid'] = idCounter
	idCounter += 1
	user['role'] = 'user'
	return encode_user(user)

def profile_for(email):
	encondedUser = unencrypted_profile_for(email)
	return aes128(pad_message(encondedUser),randomKey,1)

assert(unencrypted_profile_for("foo@bar.com") == "email=foo@bar.com&uid=0&role=user")
assert(unencrypted_profile_for("foo@bar.com") == "email=foo@bar.com&uid=1&role=user")
assert(unencrypted_profile_for("foo@bar.com&role=admin") == "email=foo@bar.comroleadmin&uid=2&role=user")

def unpad_string(string):
	if not len(string):
		return string
	order = ord(string[-1])
	if order in range(16): # this may cause to delete unnecessary characters, but we assume that the characters between 0 and 15 will not be used as part of the usernames or roles. For instance, we assume that we cannot have a role "role\n"
		if string[-order : ] == chr(order)*order:
			return string[ : -order]
		else:
			raise TypeError("Bad padding")
	return string

def decrypt_user(encryptedUser):
	decryptedUser = aes128(encryptedUser,randomKey,-1)
	decryptedUser = unpad_string(decryptedUser)
	return parse_profile(decryptedUser)

assert(decrypt_user(profile_for("test@user.com")) == { 'email': 'test@user.com', 'uid': '3', 'role': 'user'} )

if TEST:
	print("Set 2, Challenge 13:")
	print("ok" if True else "--------------FAILED--------------")

#################################################################################################

randomPreText = "".join([chr(randint(0,255)) for _ in range(randint(0,100))])
targetText = "Q29uZ3JhdHMhIE5vdyB5b3Ugc29sdmVkIHRoZSBoYXJkZXIgdmVyc2lvbiBvZiB0aGUgYnl0ZS1hdC1hLXRpbWUgRUNCIGRlY3J5cHRpb24="
targetText = bits_to_ascii(base64_to_bits(targetText))

def hardTargetEncryptionFunction(message):
	paddedMessage = pad_message(randomPreText + message + targetText)
	return aes128(paddedMessage,randomKey,1)

def find_size_of_preText(fun):
	encryptionA = fun("A")
	encryptionB = fun("B")
	cpb = -1 # cpb stands for "common prefix blocks", which is the number of blocks of 16 bytes that fun("A") and fun("B") have in common at the beggining.
	# Basically, the block where encryptionA and encryptionB are different (which, by the way, will be unique) will be the block where randomPreText ends and the message passed by the attacker begins. This will be our relevant block.
	while encryptionA[16*(cpb+1):16*(cpb+2)] == encryptionB[16*(cpb+1):16*(cpb+2)]:
		cpb += 1 # We know that we cannot get out of range because fun("A") and fun("B") should be different.
	relL = 16*(cpb+1)
	relR = 16*(cpb+2)
	# Now, we want to find the greater length of message that changes the relevant block of the final encryption, since that will give us the reminder mod 16 of the randomPreText.
	# Since we don't know if the target message starts with "AAAAAAAAAAA...", we have to compare with two different paddings: A's and B's.
	padEncA = fun("A"*16)
	padEncB = fun("B"*16)
	# In these encryptions, we know that the relevant block will be the encryption of {reminder of randomPreText} + {"AAAAAA...." or "BBBBBB...."} respectively, and when the number of A's or B's is sufficiently small, the first char of the targetText will appear, telling us the reminder of the randomPreText mod 16.
	for i in range(15,-1,-1):
		curEncA = fun("A"*i)
		curEncB = fun("B"*i)
		if padEncA[relL:relR] != curEncA[relL:relR] or padEncB[relL:relR] != curEncB[relL:relR]:
			return relL + 16 - (i+1)


def find_target_string(fun):
	cipherLen = find_size_of_cipher(fun)
	preTextLen = find_size_of_preText(fun)
	recoveredBytes = []
	recoveredText = ""
	for i in range(cipherLen-preTextLen): # this part complies the following invariant: "we already recovered the first i characters of the givenText"
		print(f"step {i}")
		assert(i == len(recoveredBytes))
		blockReminder = (-1-i-preTextLen)%16
		baitBlock = "A" * blockReminder # Now, baitBlock will have a length such that the baitBlock + the already recovered text is congruent to -1 modulo 16, so we will be able to peel the next character of the givenText analyzing the last block of this part of the message
		relB = (preTextLen + len(baitBlock)+i)//16 # relB stands for relevantBlock: this is the block we have to look to compare the bait with the actual givenText
		baitResult = fun(baitBlock)[16*relB:16*(relB+1)]
		for c in range(256):
			if fun(baitBlock + recoveredText + chr(c))[16*relB:16*(relB+1)] == baitResult:
				recoveredBytes.append(c)
				recoveredText = bytes_to_string(recoveredBytes)
				print(repr(recoveredText))
				break
	return recoveredText

def challenge14_find_target_string():
	assert(find_size_of_cipher(hardTargetEncryptionFunction) == len(targetText) + len(randomPreText)) # Now, find_size_of_cipher will give us the sum of the lengths of both added texts.
	assert(guess_encryption_type(hardTargetEncryptionFunction) == "ECB")
	assert(find_size_of_preText(hardTargetEncryptionFunction) == len(randomPreText))
	return find_target_string(hardTargetEncryptionFunction)

if TEST:
	print("Set 2, Challenge 14:")
	expected_s2c14 = "Congrats! Now you solved the harder version of the byte-at-a-time ECB decryption"
	print("ok" if challenge14_find_target_string() == expected_s2c14 else "--------------FAILED--------------")

# Note: You can also solve challenge 12 with this code calling find_target_string(targetEncryptionFunction)

#################################################################################################

assert(unpad_string("ICE ICE BABY\x04\x04\x04\x04") == "ICE ICE BABY")

exceptionRaised = False
try:
	unpad_string("ICE ICE BABY\x05\x05\x05\x05")
except TypeError:
	exceptionRaised = True
assert(exceptionRaised)

exceptionRaised = False
try:
	unpad_string("ICE ICE BABY\x01\x02\x03\x04")
except TypeError:
	exceptionRaised = True
assert(exceptionRaised)

if TEST:
	print("Set 2, Challenge 15:")
	print("ok" if True else "--------------FAILED--------------")

#################################################################################################

def c16_encryption_function(message):
	paddedMessage = pad_message("comment1=cooking%20MCs;userdata=" + message + ";comment2=%20like%20a%20pound%20of%20bacon")
	# for now I don't know what "The function should quote out the ";" and "=" characters." means
	return aes128(paddedMessage, randomKey, 1, False)

def find_admin_parameter_in_ciphertext(ciphertext):
	decryptedMessage = aes128(ciphertext, randomKey, -1, False)
	parameters = [chunk.split('=') for chunk in decryptedMessage.split(';')]
	for parameter in parameters:
		if parameter[0] == "admin" and parameter[1] == "true":
			return True
	return False

assert(not find_admin_parameter_in_ciphertext(c16_encryption_function(";admin=true")))
assert(not find_admin_parameter_in_ciphertext(c16_encryption_function("rubbish;admin=true")))

