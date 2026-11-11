from qci_pqc.coverage import reset, skip, summary

def test_a_skip_marks_partial():
    reset()
    skip("app.tar", "corrupt")
    assert summary()["partial"] is True
    assert summary()["skipped"] == ["app.tar: corrupt"]
