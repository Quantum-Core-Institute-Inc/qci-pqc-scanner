from qci_pqc.trend import append, summary

def test_trend(tmp_path):
    p = tmp_path / "trend.json"
    append(p, 70, 60, 2, 1)
    append(p, 72, 61, 0, 1)
    s = summary(p)
    assert s["points"] == 2
    assert s["latest"]["score"] == 72
