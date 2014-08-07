# -*- coding: utf8 -*-
# hw1.py
# Author: Jiangmf
# Date: 2014-08-07
#
# Let us see what goes wrong when a stream cipher key is used more than once.
# Below are eleven hex-encoded ciphertexts that are the result of encrypting
# eleven plaintexts with a stream cipher, all with the same stream cipher key.
# Your goal is to decrypt the last ciphertext, and submit the secret message
# within it as solution.
import binascii

ct = [
    '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146'
    'fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7'
    'bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e87743'
    '01fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e',
    '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44'
    'ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0'
    'bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab2417'
    '1ab3cdadb8356f',
    '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44'
    'ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5'
    'f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb',
    '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056'
    'f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4'
    'ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb7752'
    '00b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229b'
    'e6636aaa',
    '3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213'
    'f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5'
    'ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a'
    '0bb5dcaba43722130f042f8ec85b7c2070',
    '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84a'
    'ba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3'
    'f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e43643'
    '4eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9'
    'f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4',
    '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909'
    'ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5'
    'e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b17'
    '0fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287'
    'ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1e'
    'fff71ea313c8661dd9a4ce',
    '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943'
    'ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5'
    'fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac3259'
    '18b2daada43d6712150441c2e04f6565517f317da9d3',
    '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513'
    'e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0'
    'f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e93342'
    '1cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9'
    'ed6d76e48b63ab15d0208573a7eef027',
    '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005'
    'b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7'
    'f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83',
    '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052'
    'ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8'
    'f3315f4b52e301d16e9f52f904'
]

class XorDecryptor(object):

    def __init__(ciphertexts):
        self._ciphertexts = ciphertexts
        self._target = ciphertexts[-1]
        pass

    pass

#--------------------Part I:Guess----------------------------
def stringToBytes(string):
    return [string[x:x+2] for x in range(0,len(string),2)]

def byteToDec(byte):
    return eval("0x"+byte)

def decToHex(dec):
    return "%02x"%(dec)

def xor(lst1,lst2=tt_hex,index=0):
    l = min(len(lst1),len(lst2))
    result = []
    for i in range(0,l):
        result.append(decToHex(byteToDec(lst1[i]) ^ byteToDec(lst2[index+i])))
    return result

def valid(ch):
    return (ch>='41' and ch<='5a') or (ch>='61' and ch<='7a') or (ch=='00') or (ch=='20')

def charsToBytes(str):
    return map (binascii.b2a_hex,str)

def bytesToChars(hex_list):
    return map (binascii.a2b_hex,hex_list)

def bytesToString(hex_list):
    return "".join(hex_list)

def checkGuess(guess, xor_list):
    result = set()
    for i in range(0,len(xor_list)-len(guess)+1):
        test = xor(guess,xor_list,i)
        if reduce(lambda x,y:x and y,map(valid,test),True):
            result.add(i)
    return result

def checkAllGuess(guess,all_list):
    result = checkGuess(guess,all_list[0])
    for i in range(1,len(all_list)):
        result = result.intersection(checkGuess(guess,all_list[i]))
    return result

def findText(gt,ct_xor):
    guess = charsToBytes(gt)
    return map(lambda x: (x,gt),checkAllGuess(guess,ct_xor))

def setToTuples(s):
    indexex = map (lambda x:x[0],s)
    for i in range(0,len(tt)/2):
        if not i in indexex:
            s.update(set([(i,'_')]))
    return sorted(list(s),key=lambda x:x[0])

def tuplesToString(tuples):
    return bytesToString(map (lambda x:x[1],tuples))

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

# Test Code
if __name__ == "__main__":
    tt = ct[-1]
    tt_hex = stringToBytes(tt)
    ct_hex =  map(stringToBytes,ct)
    ct_xor = map(xor,ct_hex)
    mm_set = set([])

    print ct_xor

    for s in "abcdefghijklmnopqrstuvwxyz :,":
        mm_set.update(findText(s,ct_xor))

    tuples = setToTuples(mm_set)
    print tuples
    print tuplesToString(tuples)

        # machine guess result:
        # th_ secuet_mes_age is: wh__ us_______tr____cipher,_nev_r use the key more than on__



#--------------------Part II: Check and Complete----------------------------
#
## human guess result:
#mm_possible = "The secret message is: When using a stream cipher, never use the key more than once"
#
#mm_hex_possible = charsToBytes(mm_possible)
#kk_hex_possible = xor(mm_hex_possible)
#print bytesToString(kk_hex_possible)
#
#kk_hex = kk_hex_possible
##kk_hex = stringToBytes("66396e89c9dbd8cc9874352acd6395102eafce78aa7fed28a07f6bc98d29c50b69b0339a19f8aa401a9c6d708f80c066c763fef0123148cdd8e802d05ba98777335daefcecd59c433a6b268b60bf4ef03c9a61")
#mt_hex = map(lambda x:xor(x,kk_hex),ct_hex)
#mt_readable = map(bytesToString,map(bytesToChars,mt_hex))
#
#mt_gs = charsToBytes('There are two types of cryptography - that which will keep secrets safe from your l')
#
#kk_hex = xor(mt_gs,ct_hex[5])
#print bytesToString(kk_hex)
#
#print mt_readable
#
#mm_hex = xor(kk_hex,tt_hex)
#print bytesToString(bytesToChars(mm_hex))

