"""
PSEUDOCODE
1. Ask for string input
    To be expanded to support files
2. Print hasing options
3. Prompt user for which hashing algorithm to use
4. Hash string
5. Print string to user
"""

#Displays the SHA1, SHA256, SHA384, SHA512 and MD5 hash of the entered password

import hashlib

#function that prints the SHA1 hash of the entered password
def sha1_hash_function():
    print("\nSHA1 hash:")
    setpass = bytes(password, 'utf-8')
    hashObject = hashlib.sha1(setpass)
    guessPassword = hashObject.hexdigest()
    print(guessPassword)

#function that prints the SHA256 hash of the entered password
def sha256_hash_function():
    print("\nSHA256 hash:")
    setpass = bytes(password, 'utf-8')
    hashObject = hashlib.sha256(setpass)
    guessPassword = hashObject.hexdigest()
    print(guessPassword)

#function that prints the SHA384 hash of the entered password
def sha384_hash_function():
    print('\nSHA384 hash:')
    setpass = bytes(password, 'utf-8')
    hashObject = hashlib.sha384(setpass)
    guessPassword = hashObject.hexdigest()
    print(guessPassword)

#function that prints the SHA512 hash of the entered password
def sha512_hash_function():
    print('\nSHA512 hash:')
    setpass = bytes(password, 'utf-8')
    hashObject = hashlib.sha384(setpass)
    guessPassword = hashObject.hexdigest()
    print(guessPassword)

#function that prints the MD5 hash of the entered password
def md5_hash_function():
    print("\nMD5 hash:")
    setpass = bytes(password, 'utf-8')
    hashObject = hashlib.md5(setpass)
    guessPassword = hashObject.hexdigest()
    print(guessPassword)

def user_
#Asks the user for a password to hash
password = input("Input the password to hash: ")
print('\nHashing algorithms')
print("For SHA1, type 'SHA1'")
print("For SHA256, type 'SHA256'")
print("For SHA384, type 'SHA384'")
print("For SHA512, type 'SHA512'")
print("For MD5, type 'MD5'")
print("For all of the above, type 'ALL'\n")

#Prompts user and selects function based on user input
hashSelection = str(input('Type hash algorithm: '))
if hashSelection in ['sha1', 'SHA1']:
    print('SHA1 has been chosen')
    sha1_hash_function()
elif hashSelection in ['SHA256','sha256']:
    print('SHA256 has been chosen')
    sha256_hash_function()
elif hashSelection in ['SHA384','sha384']:
    print('SHA384 has been chosen')
    sha384_hash_function()
elif hashSelection in ['SHA512','sha512']:
    print('SHA512 has been chosen')
    sha512_hash_function()
elif hashSelection in ['MD5','md5']:
    print('MD5 has been chosen')
    md5_hash_function()
elif hashSelection in ['All','all']:
    print('All available hashing algorithms have been chosen')
    sha1_hash_function()
    sha256_hash_function()
    sha384_hash_function()
    sha512_hash_function()
    md5_hash_function()
else:
    print('Enter a valid input')

input('\nPress ENTER to exit')