"""Python3 implementation of AES following the FIPS197 documentation.

AES stands for Advanced Encryption Standard; this is widely the most popular
encryption standard used today. The purpose of this program is to experiment
with and learn more about AES and the algorithms it consists of. This program
should never be used for actual encryption or decryption ever. Let me repeat,
NEVER USE THIS PROGRAM FOR REAL!

Usage:
    aes = PyAES(message, key)
    aes = PyAES(message, key)

"""

import logging
from utils import get_msb, clear_k_bit, bit_count, kth_bit_set


class PyAES:
    """A class used to represent a Python implementation of AES algorithm as documented in FIPS197.

    The process for performing AES encryption is...
    The process for performing AES decryption is...

    Attributes:
        logger: Configured logger
        message: A string of the message to be decrypted or encrypted
        key: A string of the key to use for decryption
        rcon: An array of hexadecimal round constants
        sbox: An array of bytes for substitution
        inv_sbox: An array of bytes for inverse substitution
        ax: Polynomial used in mixing columns.
        mx: Irreducible polynomial
        nb: An integer of the number of bytes in the state
        nk: An integer of the number of 32-bit words in the key. (4, 6, or 8)
        nr: An integer of the number of rounds (a function of nb and nk)
        key_1d_byte_array: 1D array representation of the key
        state_1d_byte_array: 1D array representation of the state
        round_key_arr: 1D array of the key expansion for key schedule
    """

    logFormat = '%(asctime)s - %(levelname)s - %(message)s'
    # TODO: Change logging level
    logging.basicConfig(format=logFormat, level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    # Uncomment to hide debug logging
    # logger.setLevel(logging.WARNING)

    rcon = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
        0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
        0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
        0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
        0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
        0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
    ]

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
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    inv_sbox = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    ax = [
        0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02
    ]

    mx = 0x1b  # Irreducible polynomial

    nb = 4 * 4

    def __init__(self, message, key):
        self.logger.info("PyAES has been constructed")
        self.logger.debug("---------------------------------------------------")
        self.message = message
        self.logger.debug("Message: {}".format(self.message))
        self.key = key
        self.logger.debug("Key: {}".format(self.key))
        self.nk, self.nr = self.get_key_length_dependent_vars()
        self.logger.debug("Nk: {} Nr: {} Nb: {}".format(self.nk, self.nr, self.nb))
        self.key_1d_byte_array = self.convert_key_to_byte_array()
        self.logger.debug("Key Byte Array: {}".format(self.key_1d_byte_array))
        self.state_1d_byte_array = self.convert_message_to_state_array()
        self.logger.debug("State Byte Array: {}".format(self.state_1d_byte_array))
        self.round_key_arr = self.key_expansion()
        self.logger.debug("Round Key Array: {}".format(self.round_key_arr))
        self.logger.debug("Round Key Array Length: {}".format(len(self.round_key_arr)))
        self.logger.debug("---------------------------------------------------")

    def get_key_length_dependent_vars(self):
        """ Calculate variables the depend on key length.

        Some variable depend on the length of the key.
        For 128 bit key:
            Nk = 4
            Nr = 10
        For 192 bit key:
            Nk = 6
            Nr = 12
        For 256-bit key:
            Nk = 8
            Nr = 14

        Returns:
            nk: Number of words
            nr: Number of rounds

        """

        msb = get_msb(int(self.key, base=16))
        if msb <= 2 ** 127:  # Check if the key is 128-bit
            return 4, 10
        elif msb <= 2 ** 191:  # Check if the key is 192-bit
            return 6, 12
        else:  # If the key is 256-bit
            return 8, 14

    def convert_key_to_byte_array(self):
        """Coverts the key string to an array of bytes.

        The key is represented by a 1D array of bytes.

        Returns:
            1D array of bytes from the key string

        """

        # Get the byte count of the key
        byte_count = 16 if self.nr == 10 else 24 if self.nr == 12 else 32
        # Make an empty array of that size
        key = [0] * byte_count
        # Keep track of where we are in the key
        key_idx = 0
        # Store at each index, every 2 chars in the key
        for n in range(byte_count):
            key[n] = int(self.key[key_idx] + self.key[key_idx + 1], 16)
            if key_idx + 2 < len(self.key):
                key_idx += 2
        return key

    def convert_message_to_state_array(self):
        """Converts a string message into a byte array.

        The 4x4 state array is represented by a 1D array.

        state_4_by_4 = [
                [0, 1, 2, 3],
                [4, 5, 6, 7],
                [8, 9, 10, 11],
                [12, 13, 14, 15]
               ]

        state_1d = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]

        Returns:
            state: 1D representation of a 4x4 matrix of bytes

        """

        # Make an empty array of the correct size
        state = [0] * self.nb
        # Keep track of where we are in the message (by char idx)
        msg_idx = 0
        # If trailing 0 was somehow dropped (not sure why it was happening)
        if len(self.message) < 32:
            # Append the trailing 0 back on
            self.message = self.message + '0'

        # Step through each byte of the state and every 2 chars and add it to the state array
        for n in range(self.nb):
            state[n] = int(self.message[msg_idx] + self.message[msg_idx + 1], 16)
            if msg_idx + 2 < len(self.message):
                msg_idx += 2

        return state

    ###############################################################
    #                  FINITE FIELD ARITHMETIC                    #
    ###############################################################

    def ff_add(self, addend_a: int, addend_b: int) -> int:
        """Performs finite field addition of two integers.

        If a1 and a2 aren't integers, try to cast into base16 integer.
        Addition of two elements in a finite field is achieved by adding
        the coefficients for the corresponding powers in the polynomial for
        the two elements. Addition can be performed with XOR (i.e. modulo 2).
        Identical to polynomial subtraction.

        Example:
            x6 is the same as x^6.
            (x6 + x4 + x2 + x + 1) + (x7 + x + 1) = x7 + x6 + x4 + x2
            {01010111}             + {10000011}   = {11010100}
            {0x57}               XOR {0x83}       =  {0xd4}

        Args:
            addend_a: Number to be added
            addend_b: Number to be added

        Returns:
            The result of XOR-ing the two numbers

        """

        return addend_a ^ addend_b  # FF addition and subtraction with XOR

    def xtime(self, num: int) -> int:
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

        Args:
            num: binary representation of a polynomial to be multiplied by x

        Returns:
            n(x) * x

        """

        product = num << 1  # Multiply n by x (ie 00000010 or 02)
        if get_msb(product) <= 128:  # If the MSB is the 8th bit or lower
            return product  # Return because we're already reduced.

        # Reduce by XOR the polynomial m(x) = x^8 + x^4 + x^3 + x + 1
        reduced_product = product ^ self.mx
        return clear_k_bit(9, reduced_product)  # Drop the 9th bit and return

    def ff_multiply(self, a: int, b: int) -> int:
        """Performs finite filed multiplication between two numbers.

        Multiplication in GF(2^8) corresponds  with  the multiplication of polynomials
        modulo an irreducible polynomial of degree 8 (i.e. mx(x)). This can be implemented
        using xtime() and adding intermediate results.

        Args:
            a: number to be multiplied
            n: number to multiply

        Returns:
            a * b GF(2^8)

        """

        product = 0
        for times in range(8):
            # Check the first bit
            if (b & 1) == 1:
                # If the first bit is set, Add it to the product
                product = product ^ a
            # Make sure our product hasn't gone out of our range
            if product > 0x100:
                # Remove the 9th bit if set
                product = product ^ 0x100
            # Store the MSB
            msb = (a & 0x80)
            # Shift over 1 (Mulitply by 2)
            a = a << 1
            # Check if we've gone over 8 bits
            if a > 0x100:
                # Store the 8th bit of a
                a = a ^ 0x100
            # If the msb is the 9th bit
            if msb == 0x80:
                # XOR with our irreducible polynomial
                a = a ^ self.mx
            if a > 0x100:
                # Store the 8th bit of a
                a = a ^ 0x100
            # Multiply by 2 again
            b = b >> 1
            # Check if we've gone out of bounds
            if b > 0x100:
                # Store the bit
                b = b ^ 0x100
        return product

    ###############################################################
    #                          CIPHER                             #
    ###############################################################

    def encrypt(self):
        """Formats result of cipher as a string

        Returns:
            String representation of the encrypted message

        """

        return ''.join(hex(x)[2:].zfill(2) for x in self.cipher())

    def sub_bytes(self, state):
        """Substitute bytes from sbox with state array.

        sub_bytes() is a non-linear byte substitution that operates
        independently on each byte of the State using a substitution
        table (S-box).

        This S-box, which is invertible, is constructed by composing
        two transformations:
            1. Take the multiplicative inverse of GF(2^8); the element
            {00} is mapped to itself.
            2. Apply the following affine transformation (over GF(2)):
                * See FIPS197

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes replaced by sbox values

        """

        for n in range(self.nb):
            state[n] = self.sbox[state[n]]
        return state

    def shift_rows(self, state):
        """Shift the rows of the state array.

        The bytes in the last three rows of the state are cyclically shifted
        over different number of bytes (offsets). The first row, r = 0, is not
        shifted.

        Representing state as a 1D array, every 4 is a column:
            state = [
                        0, 1, 2, 3,
                        4, 5, 6, 7,
                        8, 9, 10, 11,
                        12, 13, 14, 15
                    ]

        For shifting the rows, we don't shift row 0
        Row 0 Indexes: 0, 4, 8, 12
        Row 1 Indexes: 1, 5, 9, 13
        Row 2 Indexes: 2, 6, 10, 14
        Row 3 Indexes: 3, 7, 11, 15

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes shifted around

        """

        # Row 1 Shift
        end_byte_store = state[13]  # Store the last byte of the row
        state[13] = state[1]  # First row element jumps to end of row
        # Other rows just shift by one
        state[1] = state[5]
        state[5] = state[9]
        state[9] = end_byte_store

        # Row 2 Shift
        first_byte_store = state[2]
        end_byte_store = state[14]
        state[2] = state[10]
        state[14] = state[6]
        state[10] = first_byte_store
        state[6] = end_byte_store

        # Row 3 Shift
        end_byte_store = state[15]  # Store the last byte of the row
        state[15] = state[11]  # First row element jumps to end of row
        # Other rows just shift by one
        state[11] = state[7]
        state[7] = state[3]
        state[3] = end_byte_store

        return state

    def mix_columns(self, state):
        """Transforms the state matrix column-by-column.

         The mix_columns() transformation operates on the State
        column-by-column, treating each column as a four-term
        polynomial.

        Columns are considered as polynomial over
        GF(2^8) and multiplied modulo x^4 + 1 with a(x) where
        a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

        This can be seen as matrix multiplication; let
            s'(x) = a(x) ffmult s(x)

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes with mixed columns

        """

        # Empty array of same size of state
        mixed_state = [0] * self.nb
        # Start with the first column offset
        n = 0
        # Compute the transformation column by column
        while n <= self.nb - 4:
            mixed_state[n] = self.ff_multiply(0x02, state[n]) ^ self.ff_multiply(0x03, state[n + 1]) ^ self.ff_multiply(0x01, state[n + 2]) ^ self.ff_multiply(0x01, state[n + 3])
            mixed_state[n + 1] = self.ff_multiply(0x01, state[n]) ^ self.ff_multiply(0x02, state[n + 1]) ^ self.ff_multiply(0x03, state[n + 2]) ^ self.ff_multiply(0x01, state[n + 3])
            mixed_state[n + 2] = self.ff_multiply(0x01, state[n]) ^ self.ff_multiply(0x01, state[n + 1]) ^ self.ff_multiply(0x02, state[n + 2]) ^ self.ff_multiply(0x03, state[n + 3])
            mixed_state[n + 3] = self.ff_multiply(0x03, state[n]) ^ self.ff_multiply(0x01, state[n + 1]) ^ self.ff_multiply(0x01, state[n + 2]) ^ self.ff_multiply(0x02, state[n + 3])
            n += 4  # Go to next byte offset

        return mixed_state

    def add_round_key(self, state, round_key):
        """Add the state and round key together.

        Adds the state and round key together byte by byte.

        A Round Key is added to the State by a simple bitwise XOR operation.
        Each Round Key consists of Nb words from the key schedule. Those Nb words
        are each added into the columns of the state.

        Args:
            state:
            round_key:

        Returns:
            1D array of state bytes added with round key bytes

        """

        # Go through each byte
        for n in range(self.nb):
            if n < len(round_key):
                # Finite Field Add (XOR) the state byte and round key byte
                state[n] = self.ff_add(state[n], round_key[n])

        return state

    def cipher(self):
        """Performs the cipher methods for encryption.

        This method brings everything together to encrypt
        the message the was given when this object was
        created.

        Returns:
            1D array of bytes for the encrypted message

        """
        self.logger.info("Beginning Cipher (Encryption)")
        self.logger.debug("---------------------------------------------------")
        self.logger.debug("round[0]- input: " + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.logger.debug("round[0]- k_sch: " + ''.join(format(x, 'x') for x in self.key_1d_byte_array))
        self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, self.key_1d_byte_array)
        for r in range(1, self.nr):
            self.logger.debug("---------------------------------------------------")
            self.logger.debug("round[{}]-start: ".format(r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.sub_bytes(self.state_1d_byte_array)
            self.logger.debug("round[{}]-s_box: ".format(r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.shift_rows(self.state_1d_byte_array)
            self.logger.debug("round[{}]-s_row: ".format(r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.mix_columns(self.state_1d_byte_array)
            self.logger.debug("round[{}]-m_col: ".format(r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            key_schedule = self.get_round_key(self.nb * r)
            self.logger.debug("round[{}]-k_sch: ".format(r) + ''.join(format(x, 'x') for x in key_schedule))
            self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, key_schedule)

        self.logger.debug("---------------------------------------------------")
        self.logger.debug("round[{}]-start: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.sub_bytes(self.state_1d_byte_array)
        self.logger.debug("round[{}]-s_box: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.shift_rows(self.state_1d_byte_array)
        self.logger.debug("round[{}]-s_row: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, self.get_round_key(self.nb * self.nr))
        self.logger.debug("round[{}]-k_sch: ".format(self.nr) + ''.join(f"{x: #0x}" for x in self.state_1d_byte_array))
        self.logger.debug("---------------------------------------------------")
        self.logger.debug(self.state_1d_byte_array)
        self.logger.debug("output: ".format(self.nr) + ''.join(hex(x)[2:].zfill(2) for x in self.state_1d_byte_array))
        return self.state_1d_byte_array

    def get_round_key(self, offset):
        """Get the correct round key from the key schedule.

        The round key array was generated by the key expansion
        when a PyAES object was created. This method is given
        the correct offset to extract the correct key for the
        given round.

        Args:
            offset: The offset will by in increments of 16 bytes.

        Returns:
            1D array of 16 bytes representing the round key

        """

        round_key = [0] * self.nb
        ofs = 0
        for i in range(4):
            round_key[i * 4] = self.round_key_arr[offset + ofs]
            round_key[i * 4 + 1] = self.round_key_arr[offset + ofs + 1]
            round_key[i * 4 + 2] = self.round_key_arr[offset + ofs + 2]
            round_key[i * 4 + 3] = self.round_key_arr[offset + ofs + 3]
            ofs += 4

        return round_key

    ###############################################################
    #                      INVERSE CIPHER                         #
    ###############################################################

    def decrypt(self):
        """Formats result of inverse cipher as a string.

        Returns:
            String representation of the decrypted message

        """

        return ''.join(hex(x)[2:].zfill(2) for x in self.inv_cipher())

    def inv_sub_bytes(self, state):
        """Substitute bytes from inv_sbox with state array.

        sub_bytes() is a non-linear byte substitution that operates
        independently on each byte of the State using a substitution
        table (S-box).

        This S-box, which is invertible, is constructed by composing
        two transformations:
            1. Take the multiplicative inverse of GF(2^8); the element
            {00} is mapped to itself.
            2. Apply the following affine transformation (over GF(2)):
                * See FIPS197

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes replaced by sbox values

        """

        for n in range(self.nb):
            state[n] = self.inv_sbox[state[n]]
        return state

    def inv_shift_rows(self, state):
        """Invert Shift the rows of the state array.

        The this is an inverse of the normal shift rows. Only the
        bytes of the last three rows are cyclically shifted over.
        The first row is not shifted.

        See FIPS192 5.3.1 for details.

        Representing state as a 1D array, every 4 is a column:
            state = [
                        0, 1, 2, 3,
                        4, 5, 6, 7,
                        8, 9, 10, 11,
                        12, 13, 14, 15
                    ]

        For shifting the rows, we don't shift row 0
        Row 0 Indexes: 0, 4, 8, 12
        Row 1 Indexes: 1, 5, 9, 13
        Row 2 Indexes: 2, 6, 10, 14
        Row 3 Indexes: 3, 7, 11, 15

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes shifted around

        """

        # Row 1 Shift
        last_byte_store = state[13]
        state[13] = state[9]
        state[9] = state[5]
        state[5] = state[1]
        state[1] = last_byte_store

        # Row 2 Shift
        byte_store = state[10]
        last_byte_store = state[14]
        state[10] = state[2]
        state[14] = state[6]
        state[2] = byte_store
        state[6] = last_byte_store

        # Row 3 shift
        last_byte_store = state[11]
        state[11] = state[15]
        state[15] = state[3]
        state[3] = state[7]
        state[7] = last_byte_store

        return state

    def inv_mix_columns(self, state):
        """Invert transforms the state matrix column-by-column.

        The mix_columns() transformation operates on the State
        column-by-column, treating each column as a four-term
        polynomial.

        Columns are considered as polynomial over
        GF(2^8) and multiplied modulo x^4 + 1 with a(x) where
        a(x) = {03}x^3 + {01}x^2 + {01}x + {02}

        This can be seen as matrix multiplication; let
            s'(x) = a(x) ffmult s(x)

        Args:
            state: 1D array of state bytes

        Returns:
            1D array of state bytes with mixed columns

        """

        # Initialize an empty array same size as state
        mixed_state = [0] * self.nb
        # Start at the first column
        n = 0
        # Do each column at a time
        while n <= self.nb - 4:
            mixed_state[n] = self.ff_multiply(0x0e, state[n]) ^ self.ff_multiply(0x0b, state[n + 1]) ^ self.ff_multiply(0x0d, state[n + 2]) ^ self.ff_multiply(0x09, state[n + 3])
            mixed_state[n + 1] = self.ff_multiply(0x09, state[n]) ^ self.ff_multiply(0x0e, state[n + 1]) ^ self.ff_multiply(0x0b, state[n + 2]) ^ self.ff_multiply(0x0d, state[n + 3])
            mixed_state[n + 2] = self.ff_multiply(0x0d, state[n]) ^ self.ff_multiply(0x09, state[n + 1]) ^ self.ff_multiply(0x0e, state[n + 2]) ^ self.ff_multiply(0x0b, state[n + 3])
            mixed_state[n + 3] = self.ff_multiply(0x0b, state[n]) ^ self.ff_multiply(0x0d, state[n + 1]) ^ self.ff_multiply(0x09, state[n + 2]) ^ self.ff_multiply(0x0e, state[n + 3])
            n += 4  # Move to the next column
        return mixed_state

    def inv_cipher(self):
        """Performs the inverse cipher methods for decryption.

        This method brings everything together to decrypt
        the message the was given when this object was
        created.

        Returns:
            1D array of bytes for the decrypted message

        """

        self.logger.info("Beginning Inverse Cipher (Decryption)")
        self.logger.debug("---------------------------------------------------")
        self.logger.debug("0- Input: " + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        round_key = self.get_round_key(self.nb * self.nr)
        self.logger.debug("0- Round Key: " + ''.join(format(x, 'x') for x in round_key))
        self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, round_key)
        for r in range(self.nr - 1, 0, -1):
            self.logger.debug("---------------------------------------------------")
            self.logger.debug("round[{}]-istart: ".format(self.nr - r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.inv_shift_rows(self.state_1d_byte_array)
            self.logger.debug("round[{}]-is_row: ".format(self.nr - r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.inv_sub_bytes(self.state_1d_byte_array)
            self.logger.debug("round[{}]-is_box: ".format(self.nr - r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            round_key = self.get_round_key(self.nb * r)
            self.logger.debug("round[{}]-ik_sch: ".format(self.nr - r) + ''.join(format(x, 'x') for x in round_key))
            self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, round_key)
            self.logger.debug("round[{}]-ik_add: ".format(self.nr - r) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
            self.state_1d_byte_array = self.inv_mix_columns(self.state_1d_byte_array)
        self.logger.debug("---------------------------------------------------")

        self.logger.debug("round[{}]-istart: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.inv_shift_rows(self.state_1d_byte_array)
        self.logger.debug("round[{}]-is_row: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.inv_sub_bytes(self.state_1d_byte_array)
        self.logger.debug("round[{}]-is_box: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.state_1d_byte_array = self.add_round_key(self.state_1d_byte_array, self.get_round_key(0))
        self.logger.debug("round[{}]-ik_sch: ".format(self.nr) + ''.join(format(x, 'x') for x in self.state_1d_byte_array))
        self.logger.debug("---------------------------------------------------")
        self.logger.debug(self.state_1d_byte_array)
        self.logger.debug("{}-ioutput: ".format(self.nr) + ''.join(hex(x)[2:].zfill(2) for x in self.state_1d_byte_array))
        return self.state_1d_byte_array

    ###############################################################
    #                       KEY EXPANSION                         #
    ###############################################################

    def sub_word(self, word):
        """Substitute the correct sbox value

        Args:
            word: An individual byte

        Returns:
            Sbox value for that bytes

        """

        return self.sbox[word]

    def rot_word(self, word):
        """Perform cyclic permutation of a word.

        Takes a word[a0, a1, a2, a3] as input, performs a cyclic permutation,
        then returns the word[a1, a2, a3, a0]

        Args:
            word: 1D array representing 4 byte word

        Returns:
            1D array of that 4 byte word rotated

        """

        # Store the first byte
        a_zero = word[0]
        # Rotate the first 3 bytes
        for a in range(3):
            word[a] = word[a + 1]
        # Put the first byte at the end
        word[3] = a_zero
        return word

    def key_expansion(self):
        """Generate the key schedule based on the key and key length.

        Each round will have a specific key that will need to be
        added to the state. The key expansion generates a 1D array
        that holds all of the round keys. This is known as the key
        schedule.

        Returns:
            1D array representing the key schedule

        """

        # Determine the array size based on key size
        expand_byte_size = 176 if self.nr == 10 else 208 if self.nr == 12 else 240
        # Determine byte count based on key size
        key_byte_count = 16 if self.nr == 10 else 24 if self.nr == 12 else 32
        i = 0
        # Keep track of what rcon value to use
        rcon_idx = 1
        word_bytes = [0, 0, 0, 0]

        # Make the expanded key array the correct size
        expand_key = [0] * expand_byte_size

        # Copy over the original key byte array
        for j in range(key_byte_count): expand_key[j] = self.key_1d_byte_array[j]

        i += key_byte_count
        # Calculate the key schedule
        while i < expand_byte_size:
            # Grab the bytes from the previous iteration
            for k in range(4):
                word_bytes[k] = expand_key[(i - 4) + k]

            # Jump in intervals of key_byte_count
            if i % key_byte_count == 0:
                # Rotate th bytes around in the word
                word_bytes = self.rot_word(word_bytes)
                # Sub with sbox for each byte in the word
                for r in range(4):
                    word_bytes[r] = self.sub_word(word_bytes[r])
                # XOR the word with the rcon value for the round
                word_bytes[0] = word_bytes[0] ^ self.get_rcon_value(rcon_idx)
                # Increment the rcon index
                rcon_idx += 1

            # If we have a 256-bit key
            if key_byte_count == 32 and (i % key_byte_count) == self.nb:
                # Sub sbox value for each byte in the word
                for e in range(4):
                    word_bytes[e] = self.sub_word(word_bytes[e])

            # XOR each expanded key word for this round with the word bytes
            for m in range(4):
                expand_key[i] = expand_key[i - key_byte_count] ^ word_bytes[m]
                i += 1

        # Return the key schedule (expanded key)
        return expand_key

    def get_rcon_value(self, i):
        """Get rcon value.

        Args:
            i: index for the rcon value to get

        Returns:
            a value from the rcon table

        """

        return self.rcon[i]
