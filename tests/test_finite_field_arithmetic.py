from finite_field_arithmetic import AESFiniteField

ff = AESFiniteField()


def test_add():
    assert ff.add(0x57, 0x83) == hex(0xd4)


def test_xtime():
    assert ff.xtime(0x57) == hex(0xae)
    assert ff.xtime(0xae) == hex(0x47)
    assert ff.xtime(0x47) == hex(0x8e)
    assert ff.xtime(0x8e) == hex(0x07)


def test_ff_multiply():
    assert ff.multiply(5, 5) == 25
