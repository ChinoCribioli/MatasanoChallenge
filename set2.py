from set1 import *

def challenge9_pad_block(block,desiredLength):
	assert(len(block) <= desiredLength)
	padding = desiredLength - len(block)
	c = chr(padding)
	return block + c*padding

# print("Set 2, Challenge 9:")
# ans = challenge9_pad_block("YELLOW SUBMARINE",20)
# expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
# print("ok" if ans == expected else "--------------FAILED--------------")

#################################################################################################

def challenge10_decrypt_cbc(key,ivString):
	with open('s2c10') as f:
	    stringMessage = f.read().replace('\n',"")
	message = bits_to_ascii(base64_to_bits(stringMessage))
	return aes128(message,key,-1,False,ivString)

# print("Set 2, Challenge 10:")
# expected_s2c10 = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\x04\x04\x04\x04"
# print("ok" if challenge10_decrypt_cbc("YELLOW SUBMARINE",chr(0)*16) == expected_s2c10 else "--------------FAILED--------------")

#################################################################################################

from random import randint

def random_encrypt_ecb(message):
	key = "".join([chr(randint(0,255)) for _ in range(16)])
	message = "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) + message # add 5 to 10 random bytes at the beginning
	message += "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) # append 5 to 10 random bytes at the end
	if len(message) % 16 != 0:
		message = challenge9_pad_block(message,len(message)+16-(len(message)%16))
	return aes128(message,key,1)

def random_encrypt_cbc(message):
	key = "".join([chr(randint(0,255)) for _ in range(16)])
	iv = [chr(randint(0,255)) for _ in range(16)]
	message = "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) + message # add 5 to 10 random bytes at the beginning
	message += "".join([chr(randint(0,255)) for _ in range(randint(5,10))]) # append 5 to 10 random bytes at the end
	if len(message) % 16 != 0:
		message = challenge9_pad_block(message,len(message)+16-(len(message)%16))
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

# print("Set 2, Challenge 11:")
# challenge11_guess_black_box(50) # el problema es que cuando toca cbc, la encriptacion genera que el segundo y el tercer bloque sean iguales
# print("ok")

