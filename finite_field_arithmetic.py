from utils import ByteUtils
bu = ByteUtils()

class AESFiniteField:

    def add(self, a1, a2):
        return hex(a1 ^ a2)

    def xtime(self, n):
        p = n << 1  # Multiply n1 by x (ie 00000010 or 02)
        if bu.getMSBOf(p) == 128:  # If the MSB is the 8th bit
            return hex(p)  # Return because we're already reduced.
        else:
            return hex(p ^ 0x1b)
        # if (multByX & (1 << 7)) == 0:  # Check if in reduced form by checking the 8th but (idx 7)
        #     return hex(multByX)  # Already reduced
        # else:
        #     return hex((multByX ^ 0x1b))  # Reduce by subtracting the polynomial m(x) = x^8 + x^4 + x^3 + x + 1

    def ffMultiply(self, m1, m2):
        return m1 * m2
