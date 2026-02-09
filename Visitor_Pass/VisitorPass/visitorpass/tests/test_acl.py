from acl import can


def test_acl_matrix():
    assert can("RESIDENT", "PASS", "create")
    assert not can("RESIDENT", "ENTRY_LOG", "read_all")
    assert can("GUARD", "PASS", "validate")
    assert not can("GUARD", "USER", "manage")
    assert can("ADMIN", "USER", "manage")
