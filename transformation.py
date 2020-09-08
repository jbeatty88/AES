from finite_field_arithmetic import AESFiniteField
import numpy as np

ff = AESFiniteField()


class AESTransform:
    ax = np.array([  # a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02],
    ])

    def sub_bytes(self):
        pass

    def shift_rows(self):
        pass

    def mix_columns(self, s):
        # Operate on the State <s> col-by-col
        # Treat each col as a four-term polynomial
        # Col is considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a(x)
        for col in range(4):
            self.mix_column(s[:, col])  # Calculate value for each element in col
            # Apply that back to the original state array
        pass

    def mix_column(self, col):
        byte = []
        # Unpack the state column values
        s0, s1, s2, s3 = col[0]
        # s0, s1, s2, s3 = map(int, col[0])
        print(s0)
        print(s1)
        print(s2)
        print(s3)
        # We need to calculate each element in col using all elements in col
        for i in range(4):
            # s'(x) = a(x) x s(x)
            a0, a1, a2, a3 = self.ax[i]
            # a0, a1, a2, a3 = map(int, self.ax[i])
            byte.append(
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
        print(byte)
        return byte

    def add_round_key(self):
        pass

    def inv_sub_bytes(self):
        pass

    def inv_shift_rows(self):
        pass

    def inv_mix_columns(self):
        pass
