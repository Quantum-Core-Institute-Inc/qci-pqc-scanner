from qci_pqc.report import to_html

def test_project_name_is_escaped():
    inv = type('I', (), {
        'project': '<script>alert(1)</script>',
        'findings': [],
        'scanners_used': [],
        'readiness_score': None,
        'readiness_breakdown': {},
        'coverage': {},
        'priority_findings': [],
    })()
    page = to_html(inv)
    assert '<script>alert' not in page
    assert '&lt;script&gt;' in page


def test_base64_inside_a_pem_block_is_not_an_algorithm_name(tmp_path):
    """Random key bytes can spell DH, RSA or MD5. Only the header says what the block is."""
    from qci_pqc.scanner import scan_path
    (tmp_path / "note.pem").write_text(
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\n"
        "c3RDQTAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\n"
        "x9/DH+MD5/RSA+DSA/RC4+DES/abcdefghijklmnopqrstuvwxyz0123456789AB\n"
        "-----END CERTIFICATE-----\n"
    )
    assert not [f for f in scan_path(tmp_path) if f.evidence_line == 4]
