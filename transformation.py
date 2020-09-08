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

    def mix_columns(self, s: list):
        # Operate on the State <s> col-by-col
        # Treat each col as a four-term polynomial
        # Col is considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a(x)
        for col in range(4):
            # Calculate value for each element in s column and return s' column
            s_col = s[:, col]
            s_p_col = self.mix_column(s_col)
            # Replace s column with s' column
            s[:, col] = s_p_col

    def mix_column(self, col: list):
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
        pass

    def inv_sub_bytes(self):
        pass

    def inv_shift_rows(self):
        pass

    def inv_mix_columns(self):
        pass
