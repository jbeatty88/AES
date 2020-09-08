from finite_field_arithmetic import AESFiniteField

ff = AESFiniteField()


def test_add():
    assert hex(ff.add(0x57, 0x83)) == hex(0xd4)


def test_xtime():
    assert hex(ff.xtime(0x57)) == hex(0xae)
    assert hex(ff.xtime(0xae)) == hex(0x47)
    assert hex(ff.xtime(0x47)) == hex(0x8e)
    assert hex(ff.xtime(0x8e)) == hex(0x07)


def test_ff_multiply():
    assert hex(ff.multiply(0x57, 0x13)) == hex(0xfe)
