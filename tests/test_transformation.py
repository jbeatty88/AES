from transformation import AESTransform
import numpy as np
t = AESTransform()

state_mat_hex = [
    [0xae, 0xde, 0xde, 0xda],
    [0x3e, 0xd0, 0xad, 0xbe],
    [0xa7, 0x0d, 0xef, 0xde],
    [0xdf, 0xf4, 0xad, 0xbe],
]
state_mat_int = np.array([
    [0, 1, 2, 3],
    [4, 5, 6, 7],
    [8, 9, 10, 11],
    [12, 13, 14, 15],
])

state_mat_int_col1 = np.array([[0, 4, 8, 12]])

def test_mix_columns():
    t.mix_columns(state_mat_int)
    assert True

def test_mix_column():
    b = t.mix_column(state_mat_int_col1)