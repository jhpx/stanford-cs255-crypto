# -*- coding: utf8 -*-
# hw6.py
# Author: Jiangmf
# Date: 2014-08-07
#
# Factoring challenge #1:
# Find the smaller of the two factors where N = p * q and
#                       |p-q| < 2N^(1/4)
#
# Factoring challenge #2:
# Find the smaller of the two factors where N = p * q and
#                       |p-q| < 2^11 * N^(1/4)
#
# Factoring challenge #3:
# Find the smaller of the two factors where N = p * q and
#                       |3p-2q| < N^(1/4)
#
# Factoring challenge #4:
# Use the factorization from Q1 to decrypt a challenge ciphertext
from gmpy2 import mpz, isqrt, mul, is_prime, invert, powmod
import time

N1 = mpz(
    '17976931348623159077293051907890247336179769789423065727343008115'
    '77326758055056206869853794492129829595855013875371640157101398586'
    '47833778606925583497541085196591615128057575940752635007475935288'
    '71082364994994077189561705436114947486504671101510156394068052754'
    '0071584560878577663743040086340742855278549092581')

N2 = mpz(
    '6484558428080716696628242653467722787263437207069762630604390703787'
    '9730861808111646271401527606141756919558732184025452065542490671989'
    '2428844841839353281972988531310511738648965962582821502504990264452'
    '1008852816733037111422964210278402893076574586452336833570778346897'
    '15838646088239640236866252211790085787877')


N3 = mpz(
    '72006226374735042527956443552558373833808445147399984182665305798191'
    '63556901883377904234086641876639384851752649940178970835240791356868'
    '77441155132015188279331812309091996246361896836573643119174094961348'
    '52463970788523879939683923036467667022162701835329944324119217381272'
    '9276147530748597302192751375739387929')

ciphertext4 = mpz(
    '220964518674103817763065611348834180174100697878928310717318391436761'
    '356001205380042823296504735094243439462197515122564658399679428894607'
    '645420405815647489880137348641204523252293201764879166664029975091887'
    '299716905260832220677716000193292608700095799937240774589677736978175'
    '71267229951148662959627934791540')
e = 65537


def findFactors(N, range, div1=1, div2=1):
    N = mul(N, div1 * div2)
    sqrtN = isqrt(N)
    for i in xrange(1, range + 1):
        A = sqrtN + i
        x = isqrt(A ** 2 - N)
        p = A - x
        q = A + x
        if mul(p, q) == N and is_prime(p / div1) and is_prime(q / div2):
            return p / div1, q / div2
    return None


def crackRSA(c, p, q, e):
    N = mul(p, q)
    phiN = mul(p - 1, q - 1)
    d = invert(e, phiN)
    return powmod(c, d, N)

# Test Code
if __name__ == "__main__":
    t1 = time.time()

    print "The answer for Q1 is:\n" + str(min(findFactors(N1, 1)))
    print "The answer for Q2 is:\n" + str(min(findFactors(N2, mpz(2 ** 20))))
    print "The answer for Q3 is:\n" + str(min(findFactors(N3, 1, 6, 4)))

    p, q = findFactors(N1, 1)
    pkcs = hex(crackRSA(ciphertext4, p, q, e))
    msg = pkcs[pkcs.find('00') + 2:]
    print "The answer for Q4 is:\n" + msg.decode("hex")
