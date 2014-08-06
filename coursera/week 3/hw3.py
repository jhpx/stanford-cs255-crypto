# -*- coding: utf8 -*-
# hw3.py
# Author: Jiangmf
# Date: 2014-08-06
#
# compute the hash h0 of a given file F and to verify blocks of F as they are
# received by the client.
from Crypto.Hash import SHA256
import time


def sha256(filename):
    block = []
    with open(filename, 'rb') as file:
        while True:
            bk = file.read(1024)
            if not bk:
                break
            block.append(bk)

    t = ''
    for i in range(len(block)):
        m = block[-1 - i] + t
        t = SHA256.new(m).digest()

    return t.encode("hex")

# Test Code
if __name__ == "__main__":
    t1 = time.time()

    print sha256('target.mp4')

    t2 = time.time()
    print "time:", t2 - t1
