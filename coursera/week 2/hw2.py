# -*- coding: utf8 -*-
# hw2.py
# Author: Jiangmf
# Date: 2014-08-06
#
# Implement both encryption and decryption under CBC and CTR mode
# based on built-in AES functions in PyCrypto library.

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import time

key = [x.decode('hex') for x in ["140b41b22a29beb4061bda66b6747e14",
                                 "36f18357be4dbd77f050515c73fcf9f2"]]
ciphertext = [x.decode('hex') for x in [
    "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81",
    "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253",
    "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329",
    "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"
]]


def encryption_cbc(key, plaintext):
    iv = Random.new().read(AES.block_size)
    # using PKCS5 padding
    paddings = AES.block_size - len(plaintext) % AES.block_size
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext + paddings * str(paddings))


def decryption_cbc(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    # remove paddings
    return plaintext.rstrip(plaintext[-1])


def encryption_ctr(key, plaintext):
    iv = Random.new().read(AES.block_size)
    ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return iv + cipher.encrypt(plaintext)


def decryption_ctr(key, ciphertext):
    iv = ciphertext[:16]
    ctr = Counter.new(128, initial_value=long(iv.encode("hex"), 16))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(ciphertext[16:])

# Test Code
if __name__ == "__main__":
    t1 = time.time()
    print '--Part I-- Test decryption under CBC mode:'
    for i in range(2):
        print decryption_cbc(key[0], ciphertext[i])

    print '--Part II-- Test decryption under CTR mode:'
    for i in range(2, 4):
        print decryption_ctr(key[1], ciphertext[i])

    print '--Part III-- Test encryption under CBC mode:'
    print decryption_cbc(key[0], encryption_cbc(key[0], 'CBC Correct!'))

    print '--Part IV-- Test encryption under CTR mode:'
    print decryption_ctr(key[1], encryption_ctr(key[1], 'CTR Correct!'))

    t2 = time.time()
    print "time:", t2 - t1
