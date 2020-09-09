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
    def bit_count(self, n):
        """Count how many bits set in n

        Count the number of bits in n that are set.

        :param n: The number whose bits we want to count
        :return: The number of bits set as an integer
        """
        count = 0
        while n:
            n &= n - 1
            count += 1
        print("BITCOUNT: {}".format(count))
        return count

    def get_msb(self, n: int) -> int:
        """Return the value of the most significant bit

        Get the value of the most significant bit of n.

        :param n: The number whose msb we want to check
        :return: The most significant bit of n as an integer
        """
        msb = (2 ** int(math.log(n, 2)))
        # print("MSB of {} is {}".format(bin(n), msb))
        return msb

    def clear_k_bit(self, k, n):
        """Clear the kth bit of n

        Clear the kth bit of the integer n.

        :param k: The bit we want cleared (set to 0)
        :param n: The number whose bits we want to (possibly) clear
        :return: None
        """

        return (n & (~(1 << (k - 1))))

    def kth_bit_set(self, k, n):
        """Checks if the kth bit of n is set

        Check if the kth bit of the integer n is a 0 (not set) or a 1 (set)

        :param k: The bit we want to check
        :param n: The number whose bits we want to check
        :return: True if set, False if not set
        """

        if n & (1 << k):
            return True
        else:
            return False
