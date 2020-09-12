from utils import bit_count

def test_bit_count():
    assert(bit_count(0xae) == 5)
    assert(bit_count(0xf7) == 7)