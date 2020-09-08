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

    def add(self, a1, a2):
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

        try:
            a1_int = int(a1, 16)
            a2_int = int(a2, 16)
        except:
            a1_int = a1
            a2_int = a2
        return hex(a1_int ^ a2_int)  # FF addition and subtraction with XOR

    def xtime(self, n):
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
            return hex(p)  # Return because we're already reduced.
        else:
            p1 = p ^ self.mx  # Reduce by XOR the polynomial m(x) = x^8 + x^4 + x^3 + x + 1
            return hex(bu.clear_k_bit(9, p1))  # Drop the 9th bit and return

    def multiply(self, f1, f2):
        """Performs finite filed multiplication between two numbers.

        Multiplication in GF(2^8) corresponds  with  the multiplication of polynomials
        modulo an irreducible polynomial of degree 8 (i.e. mx(x)). This can be implemented
        using xtime() and adding intermediate results

        :param f1: factor1
        :param f2: factor2
        :return: f1 * f2 GF(2^8)
        """
        return f1 * f2
