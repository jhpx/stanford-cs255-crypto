# -*- coding: utf8 -*-
# hw5.py
# Author: Jiangmf
# Date: 2014-08-07
#
# Find x such that h = g^x in Zp.
# Each of p, g, h is about 153 digits.

from gmpy2 import mpz, powmod
import time
p = mpz(
    '134078079299425970995740249982058461274793658205923933'
    '77723561443721764030073546976801874298166903427690031'
    '858186486050853753882811946569946433649006084171')
g = mpz(
    '11717829880366207009516117596335367088558084999998952205'
    '59997945906392949973658374667057217647146031292859482967'
    '5428279466566527115212748467589894601965568')
h = mpz(
    '323947510405045044356526437872806578864909752095244'
    '952783479245297198197614329255807385693795855318053'
    '2878928001494706097394108577585732452307673444020333')

B = pow(mpz(2), 20)


def dlog(p, g, h, B):
    left = {(h * powmod(g, -i, p)) % p: i for i in xrange(B)}
    gB = powmod(g, B, p)
    for x0 in xrange(B):
        v = powmod(gB, x0, p)
        if v in left:
            return x0, left[v]
    return None

# Test Code
if __name__ == "__main__":
    t1 = time.time()

    x = dlog(p, g, h, B)
    print 'x0 = ' + str(x[0])
    print 'x1 = ' + str(x[1])
    print 'x = ' + str((x[0] * B + x[1]))

    t2 = time.time()
    print "time:", t2 - t1
