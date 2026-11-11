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
