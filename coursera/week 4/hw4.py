import urllib2
import sys
import time

TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------


class PaddingOracle(object):

    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:
            if e.code == 404:
                return True  # good padding
            return False  # bad padding

    def attack(self, c):
        g = list('\0' * (len(c)))
        for block in range(len(c) / 16 - 1, -1, -1):
            for p in range(15, -1, -1):
                for i in range(0, 256):
                    pos = (block - 1) * 16 + p
                    g[pos] = chr(i)
                    sg = list(g)
                    for q in range(block * 16, len(c)):
                        sg[q] = '\0'
                    fillchar = chr(16 - p)
                    padstr = '\0' * (pos) + fillchar * (16 - p) + '\0' * 16
                    outstr = strxor(c, strxor(sg, padstr))

                    # print 'sg=' + ''.join(sg).encode('hex')
                    # print ' p=' + padstr.encode('hex')
                    # print ' o=' + ''.join(outstr).encode('hex')

                    sys.stdout.write(
                        '#({:2d}, {:2d}) = [{:3d}] = {:2x}: {:s}\r'.format(
                            block, p, pos, i, ''.join(g)))
                    sys.stdout.flush()

                    if self.query(''.join(outstr).encode('hex')):
                        break

                    if i >= 255:
                        g[pos] = chr(16 - p)
        return g

#--------------------------------------------------------------


def strxor(a, b):
    return [chr(ord(aa) ^ ord(bb)) for aa, bb in zip(a, b)]

c = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'.decode(
    'hex')

# Test Code
if __name__ == "__main__":
    t1 = time.time()

    g = PaddingOracle().attack(c)

    print "The g is '{}'".format(''.join(g))
    print "    (HEX) {}".format(''.join(g).encode('hex'))

    t2 = time.time()
    print "time:", t2 - t1
