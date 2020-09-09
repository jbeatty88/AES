from utils import ByteUtils

bu = ByteUtils()


class AESFiniteField:
    """A class used to represent finite field arithmetic

    ...

    Attributes
    ---------
    mx : int
        hexadecimal representation of the irreducible polynomial
        m(x) = x8 + x4 + x3 + x + 1

    Methods
    -------
    add(a1, a2)
        Performs finite field add of two integers
    xtime(n)
        Performs finite field multiplication by x
    multiply(m1, m2)
        Performs finite filed multiplication between two numbers
     """

    mx = 0x1b

    def add(self, a1: int, a2: int) -> int:
        """Performs finite field addition of two integers.

        If a1 and a2 aren't integers, try to cast into base16 integer.
        Addition of two elements in a finite field is achieved by adding
        the coefficients for the corresponding powers in the polynomial for
        the two elements. Addition can be performed with XOR (i.e. modulo 2).
        Identical to polynomial subtraction.

        Example
        -------
        x6 is the same as x^6.
        (x6 + x4 + x2 + x + 1) + (x7 + x + 1) = x7 + x6 + x4 + x2
        {01010111}             + {10000011}   = {11010100}
        {0x57}               XOR {0x83}       =  {0xd4}

        Parameters
        ----------
        :param a1: addend 1
        :param a2: addend 2
        :return: a1 XOR a2
        """

        return a1 ^ a2  # FF addition and subtraction with XOR

    def xtime(self, n: int) -> int:
        """Performs finite field multiplication by x.

        Multiplying the binary polynomial (b) by polynomial x results in
        *(xn == x^n)
        b7x8 + b6x7 + b5x6 + b4x5 + b3x4 + b2x3 + b1x2 + b0x

        The result of x * b(x) is obtained by reducing the above result modulo x.
        If b7 = 0, the result is already reduced. If b7 = 1, the result must be XOR
        with polynomial m(x).

        It  follows  that  multiplication  by  x  (i.e.,{00000010}  or  {02})  can
        be  implemented  at  the  byte  level  as  a  left  shift  and  a  subsequent
        conditional  bitwise  XOR  with  {1b}

        Multiplication by higher powers of x can be implemented by repeated application
        of xtime(). By adding intermediate results, multiplication by any constant can
        be implemented.

        :param n: binary polynomial to be multiplied by x
        :return: n(x) * x
        """
        p = n << 1  # Multiply n by x (ie 00000010 or 02)
        if bu.get_msb(p) == 128:  # If the MSB is the 8th bit
            return p  # Return because we're already reduced.
        else:
            p1 = p ^ self.mx  # Reduce by XOR the polynomial m(x) = x^8 + x^4 + x^3 + x + 1
            return bu.clear_k_bit(9, p1)  # Drop the 9th bit and return

    def multiply(self, f1: int, f2: int) -> int:
        """Performs finite filed multiplication between two numbers.

        Multiplication in GF(2^8) corresponds  with  the multiplication of polynomials
        modulo an irreducible polynomial of degree 8 (i.e. mx(x)). This can be implemented
        using xtime() and adding intermediate results.

        :param f1: factor1
        :param f2: factor2
        :return: f1 * f2 GF(2^8)
        """

        # Make the table with all the xtime values for f1
        xtime_table = self.make_xtime_table(f1, f2)
        product = 0
        # Check each bit of f2
        for k in range(8):
            # If k bit of f2 is set, that represent a polynomial value of x^k
            if bu.kth_bit_set(k, f2):
                # Add it to the product
                product = self.add(product, xtime_table[k])
        # Return the produc
        return product

    def make_xtime_table(self, f1: int, f2: int) -> list:
        """Creates a table of xtime results.

        When multiplying by higher powers of x, the product is found by
        adding together intermediate xtime results.

        :param f1: factor
        :param f2: factor
        :return: a list of xtime results
        """

        # Xtime table will have 8 elements, corresponding with 8 bits
        xtime_table = [0] * 63
        # First element is f1 multiplicand
        xtime_table[0] = f1
        p = f1
        # Keep track of where to place the xtime result in the table
        idx = 1
        # Compute Xtime until f2 multiplier can't be divided anymore
        while f2 != 1:
            # Compute xtime of number
            p = self.xtime(p)
            # Add it to table at correct index
            xtime_table[idx] = p
            # Increment index
            idx += 1
            # Divide f2
            f2 >>= 1
        # Return the xtime table
        return xtime_table
