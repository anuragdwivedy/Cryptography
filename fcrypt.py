import os
import sys

from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#function to encrypt data using AES in GCM mode
def encryptData(key, plainText, associated_Data):
	iv = os.urandom(16)

	encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
	encryptor.authenticate_additional_data(associated_Data)
	ciphertext = encryptor.update(plainText) + encryptor.finalize()

	return (iv, ciphertext, encryptor.tag)

#function to decrypt data
def decryptData(key, associated_data, iv, cipherText, tag):
	decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
	decryptor.authenticate_additional_data(associated_data)
	return decryptor.update(cipherText) + decryptor.finalize()

#main function
def main():
	
	key = os.urandom(32) # generate a random key
	authtag_str = "NetworkSecurityPS2AuthStr"

	# check for encryption functionality. 
	if sys.argv[1] == "-e":
	  try: 	
		inputFile = open(sys.argv[4], 'r')
		data = inputFile.read()
		iv, cipherText, tag = encryptData(key,data,authtag_str) #encrypt the data read from filr
	  except:
		print 'Error in reading input file'
		sys.exit()

	  try:
		#read the keys from argument
		senderprivatekeyFile = open(sys.argv[3], "rb")
		with senderprivatekeyFile as key_file:
			sender_private_key = serialization.load_der_private_key(
				key_file.read(),
				password = None,
				backend = default_backend()
			)
		
		destnpublickeyFile = open(sys.argv[2], "rb")
		with destnpublickeyFile as key_file:
			destination_public_key = serialization.load_der_public_key(
				key_file.read(),
				backend = default_backend()
			)

	  except:
		print 'Error in reading keys.'
		sys.exit()
	
	  try:	
		# encrypt the aes key with destination's public key
		ciphertext_key = destination_public_key.encrypt(
			key,
			padding.OAEP(
				mgf = padding.MGF1(algorithm = hashes.SHA1()),
				algorithm = hashes.SHA1(),
				label = None
			)
		)
	  except:
		print 'Error in encrypting key'
		sys.exit()

	  try:
		# signing using sender's private key
		signer = sender_private_key.signer(
			padding.PSS(
				mgf = padding.MGF1(hashes.SHA256()),
				salt_length = padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
	  except:
		print 'Error in signing key'
		sys.exit()
	  try:
		signer.update(ciphertext_key)
		signature_ciphertext_key = signer.finalize() 
	  			
	 	#create the cipher file to be sent with encrypted key, signed key , iv , tag and encrypted data
	 	cipherFile = open(sys.argv[5], 'w+')
	 	cipherFile.write(ciphertext_key)
	 	cipherFile.write(";;")
	 	cipherFile.write(signature_ciphertext_key)
	 	cipherFile.write(";;")
	 	cipherFile.write(iv)
	 	cipherFile.write(";;")
	 	cipherFile.write(tag)
	 	cipherFile.write(";;")
	 	cipherFile.write(cipherText)
	 	cipherFile.flush()
	 	cipherFile.close()
	 	inputFile.close()
	  except:
		print 'Error in writing cipher text'
		sys.exit()
	 

	# check for decryption functionality.
	if sys.argv[1] == "-d":
	  try:
		cipherText = open(sys.argv[4], 'r')
		str1 = cipherText.read()
		#detrmine keys iv and encrypted data
		ciphertext_key, signature_ciphertext_key, iv1, tag1, ciphertext1 = str1.split(";;")

		#read the keys from argument for decrytion
		destnprivatekeyFile = open(sys.argv[2],"rb")
		
		with destnprivatekeyFile as key_file:
			destination_private_key = serialization.load_der_private_key(
				key_file.read(),
				password = None,
				backend = default_backend()
			)
		
		senderpublickkeyFile = open(sys.argv[3],"rb")
		
		with senderpublickkeyFile as key_file:
			sender_public_key = serialization.load_der_public_key(
				key_file.read(),
				backend = default_backend()
			)
	 
		#verify signature using sender's public key
		verifier = sender_public_key.verifier(
			signature_ciphertext_key,
			padding.PSS(
				mgf = padding.MGF1(hashes.SHA256()),
				salt_length = padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		verifier.update(ciphertext_key)

		
		#decrypt the key using the destination' private key	
		decryptedKey = destination_private_key.decrypt(
			ciphertext_key,
			padding.OAEP(
				mgf = padding.MGF1(algorithm = hashes.SHA1()),
				algorithm = hashes.SHA1(),
				label = None
			)
		)
	 
		inputText = open(sys.argv[5], 'w')
		inputText.write(decryptData(decryptedKey,authtag_str,iv1,ciphertext1,tag1)) #decrypt the data
		inputText.close()
	  except:
		print 'Error while decrypting'
		sys.exit()	
	
if __name__ == "__main__":
	if(len(sys.argv) < 5) :
		print 'Usage : program -e/-d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
		sys.exit()
	if(sys.argv[1] not in ['-e','-d']): 
		print 'Usage : program -e/-d destination_private_key_filename sender_public_key_filename ciphertext_file output_plaintext_file'
		sys.exit()
	main()

