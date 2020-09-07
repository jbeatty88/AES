from utils import ByteUtils

bu = ByteUtils()


class AESFiniteField:

    def add(self, a1, a2):
        return hex(a1 ^ a2)  # FF addition and subtraction with XOR

    def xtime(self, n):
        p = n << 1  # Multiply n by x (ie 00000010 or 02)
        if bu.get_msb(p) == 128:  # If the MSB is the 8th bit
            return hex(p)  # Return because we're already reduced.
        else:
            p1 = p ^ 0x1b  # Reduce by XOR the polynomial m(x) = x^8 + x^4 + x^3 + x + 1
            return hex(bu.clear_k_bit(9, p1))  # Drop the 9th bit and return

    def multiply(self, m1, m2):
        return m1 * m2
