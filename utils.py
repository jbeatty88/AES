import math


class ArithmeticUtils:
    def extended_euclid(self, a, b):
        # Input: Two positive integers a >= b >= 0
        # Output: Integers x, y, d st. d = gcd(a, b) and ax + by = d
        if b == 0:
            return 1, 0, a
        x, y, d = self.extended_euclid(b, a % b)
        print("{} = gcd({}, {}) and {}*{} + {}*{} = {}".format(d, a, b, a, x, b, y, d))
        return y, x - ((a / b) * y), d


class ByteUtils:
    def bit_count(self, int_type):
        count = 0
        while int_type:
            int_type &= int_type - 1
            count += 1
        print("BITCOUNT: {}".format(count))
        return count

    def get_msb(self, n:int) -> int:
        msb = (2 ** int(math.log(n, 2)))
        # print("MSB of {} is {}".format(bin(n), msb))
        return msb

    def clear_k_bit(self, k, n):
        return (n & (~(1 << (k - 1))))

    def kth_bit_set(self, k, n):
        if n & (1 << k):
            return True
        else:
            return False

