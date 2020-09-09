from finite_field_arithmetic import AESFiniteField
import numpy as np

ff = AESFiniteField()


class AESTransform:
    """A class used to represent all of the cipher transformations

    ...

    Attributes
    ----------
    ax : matrix representation of a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

    Methods
    -------
    sub_bytes()
        Coming Soon
    shift_rows()
        Coming Soon
    mix_columns(s)
        Transforms the state matrix column-by-column
    mix_column(s)
        Transforms each column item by multiply modulo x4 + 1 with a(x)
    add_round_key()
        Coming Soon
    inv_sub_bytes()
        Coming Soon
    inv_shift_rows()
        Coming Soon
    inv_mix_columns()
        Coming Soon


    """
    ax = np.array([  # a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ])

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

    def mix_columns(self, s: list):
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

    def mix_column(self, col: list):
        """Transforms each column item by multiply modulo x4 + 1 with a(x)

        This is a helper method for mix_columns(). The arithmetic
        is done here. For each item in the column, calculate the
        transformed value by multiplying each column element by
        each row element of a(x). The column elements can be
        thought of as row index for a(x).

        :param col: a list of state column values
        :return: a list of transformed state column values
        """

        bytes = []
        # Unpack the state column values
        s0, s1, s2, s3 = col[0]

        # We need to calculate each element in col using all elements in col
        for i in range(4):
            # s'(x) = a(x) x s(x)
            a0, a1, a2, a3 = self.ax[i]
            # a0, a1, a2, a3 = map(int, self.ax[i])
            bytes.append(
                ff.add(
                    ff.add(
                        ff.multiply(s0, a0),
                        ff.multiply(s1, a1)
                    ),
                    ff.add(
                        ff.multiply(s2, a2),
                        ff.multiply(s3, a3)
                    )
                )
            )
        return bytes

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
