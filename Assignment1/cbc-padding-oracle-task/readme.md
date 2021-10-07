First assignment - cbc_part_1.py
When executed, the padding oracle attack runs - gets an encrypted token from the server, decrypts it and prints it to the console.

Second assignment - cbc_part_2.py 
When executed, the padding oracle attack runs - this time with a chosen plaintext consisting of 'I should have used authenticated encryption because ...' + <secret from assignment 1>
From this the valid ciphertext is found, and this is used to get a quote from the server, which is printed to the console
