# Cryptography
Python application that can be used to encrypt and sign a file to be sent by email


# Usage for encryption:
	python fcrypt.py -e destination_public_key.der sender_private_key.der input_plaintext_file.txt ciphertext_file.txt

# Required files for encryption should be in the same folder as the script:
	destination_public_key.der 
	sender_private_key.der 
	input_plaintext_file.txt
	
# Usage for decryption:
	python fcrypt.py -d destination_private_key.der sender_public_key.der ciphertext_file.txt output_plaintext_file.txt

# Required files for decryption should be in the same folder as the script:
	destination_private_key.der 
	sender_public_key.der 
	ciphertext_file.txt
