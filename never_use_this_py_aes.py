import numpy as np

from utils import get_msb, clear_k_bit, bit_count, kth_bit_set


class PyAES:

    def __init__(self, message, key=None):
        self.message = message
        self.key = key
        if key is None:
            self.mode = 'encrypt'
        else:
            self.mode = 'decrypt'

    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

    mx = 0x1b
    ax = np.array([  # a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ])

    def ff_add(self, a1: int, a2: int) -> int:
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
        if get_msb(p) <= 128:  # If the MSB is the 8th bit or lower
            return p  # Return because we're already reduced.
        else:
            p1 = p ^ self.mx  # Reduce by XOR the polynomial m(x) = x^8 + x^4 + x^3 + x + 1
            return clear_k_bit(9, p1)  # Drop the 9th bit and return

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

    def ff_multiply(self, f1: int, f2: int) -> int:
        """Performs finite filed multiplication between two numbers.

        Multiplication in GF(2^8) corresponds  with  the multiplication of polynomials
        modulo an irreducible polynomial of degree 8 (i.e. mx(x)). This can be implemented
        using xtime() and adding intermediate results.

        :param f1: factor1
        :param f2: factor2
        :return: f1 * f2 GF(2^8)
        """

        # Optimized by choosing the factor with fewer bytes as multiplier
        if bit_count(f1) < bit_count(f2):
            f1 = f1 ^ f2
            f2 = f1 ^ f2
            f1 = f1 ^ f2

        # Make the table with all the xtime values for f1
        xtime_table = self.make_xtime_table(f1, f2)
        product = 0
        # Check each bit of f2
        for k in range(8):
            # If k bit of f2 is set, that represent a polynomial value of x^k
            if kth_bit_set(k, f2):
                # Add it to the product
                product = self.ff_add(product, xtime_table[k])
        # Return the product
        return product

    def sub_bytes(self):
        """

        sub_bytes() is a non-linear byte substitution that operates
        independently on each byte of the State using a substitution
        table (S-box).

        This S-box, which is invertible, is constructed by composing
        two transformations:
            1. Take the multiplicative inverse of GF(2^8); the element
            {00} is mapped to itself.
            2. Apply the following affine transformation (over GF(2)):
                * See FIPS197
        :return:
        """
        pass

    def shift_rows(self):
        """

        The bytes in the last three rows of the state are cyclically shifted
        over different number of bytes (offsets). The first row, r = 0, is not
        shifted.

        :return:
        """
        pass

    def mix_column(self, col):
        """Transforms each column item by multiply modulo x4 + 1 with a(x)

        This is a helper method for mix_columns(). The arithmetic
        is done here. For each item in the column, calculate the
        transformed value by multiplying each column element by
        each row element of a(x). The column elements can be
        thought of as row index for a(x).

        :param col: a list of state column values
        :return: a list of transformed state column values
        """

        transformed_bytes = []
        # Unpack the state column values
        s0, s1, s2, s3 = col[0]

        # We need to calculate each element in col using all elements in col
        for i in range(4):
            # s'(x) = a(x) x s(x)
            a0, a1, a2, a3 = self.ax[i]
            # a0, a1, a2, a3 = map(int, self.ax[i])
            transformed_bytes.append(
                self.ff_add(
                    self.ff_add(
                        self.ff_multiply(s0, a0),
                        self.ff_multiply(s1, a1)
                    ),
                    self.ff_add(
                        self.ff_multiply(s2, a2),
                        self.ff_multiply(s3, a3)
                    )
                )
            )
        return transformed_bytes

    def mix_columns(self, s):
        """Transforms the state matrix column-by-column.

        The mix_columns() transformation operates on the State
        column-by-column, treating each column as a four-term
        polynomial.

        Columns are considered as polynomial over
        GF(2^8) and multiplied modulo x^4 + 1 with a(x) where
        a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

        This can be seen as matrix multiplication; let
            s'(x) = a(x) ffmult s(x)

        :param s: 4 x 4 state matrix
        :return: None, modifies original matrix to be s'(x)
        """

        for col in range(4):
            # Calculate value for each element in s column and return s' column
            s_col = s[:, col]
            s_p_col = self.mix_column(s_col)
            # Replace s column with s' column
            s[:, col] = s_p_col

    def add_round_key(self):
        """

        A Round Key is added to the State by a simple bitwise XOR operation.
        Each Round Key consists of Nb words from the key schedule. Those Nb words
        are each added into the columns of the state.

        :return:
        """
        pass

    def inv_sub_bytes(self):
        pass

    def inv_shift_rows(self):
        pass

    def inv_mix_columns(self):
        pass

    def sub_word(self):
        """

        Takes four-byte input word and applies the S-box to each
        of the four bytes to produce an output word.

        :return:
        """
        pass

    def rot_word(self):
        """

        Takes a word[a0, a1, a2, a3] as input, performs a cyclic permutation,
        then returns the word[a1, a2, a3, a0]

        :return:
        """
        pass
