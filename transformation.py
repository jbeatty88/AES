from finite_field_arithmetic import AESFiniteField

ff = AESFiniteField()


class AESTransform:
    def sub_bytes(self):
        pass

    def shift_rows(self):
        pass

    def mix_columns(self, s):
        # Operate on the State <s> col-by-col
        # Treat each col as a four-term polynomial
        # Col is considered as polynomials over GF(2^8) and multiplied modulo x^4 + 1 with a(x)
        # a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
        # s'(x) = a(x) x s(x)
        for col in s:
            self.mix_column(col)
        pass

    def mix_column(self, col):
        # We need to calculate each element in col using all elements in col
        nb = 4
        for i, r in enumerate(col):
            col[i] = ff.add(
                1, 2
            )

        pass

    def add_round_key(self):
        pass

    def inv_sub_bytes(self):
        pass

    def inv_shift_rows(self):
        pass

    def inv_mix_columns(self):
        pass
