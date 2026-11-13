"""TLS as configured: protocol versions that are enabled and cipher suites that are named."""
import textwrap

import pytest

from qci_pqc import tls
from qci_pqc.scanner import scan_path


def fams(line, suffix=".conf"):
    return [h.family for h in tls.hits_in(line, suffix)]


def test_openssl_names_become_iana_names():
    assert fams("ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA:AES256-SHA;") == [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"]
    assert tls.OPENSSL_TO_IANA["ECDHE-ECDSA-CHACHA20-POLY1305"] == "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    assert tls.OPENSSL_TO_IANA["DHE-RSA-AES256-SHA256"] == "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
    assert tls.OPENSSL_TO_IANA["ECDHE-RSA-AES256-SHA384"] == "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
    assert tls.OPENSSL_TO_IANA["RC4-MD5"] == "TLS_RSA_WITH_RC4_128_MD5"


@pytest.mark.parametrize("line,expected", [
    ("SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA", ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA"]),
    ("ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256", ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]),
    ("      - TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]),
    ("server.ssl.ciphers=SSL_RSA_WITH_3DES_EDE_CBC_SHA", ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]),
])
def test_suites_in_config_files(line, expected):
    assert fams(line) == expected


def test_a_suite_taken_out_of_the_list_is_not_reported():
    assert fams("SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:!RC4-SHA:-DES-CBC3-SHA") == ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]


def test_an_openssl_name_needs_a_line_that_sets_ciphers():
    assert fams("description: migrated from AES128-SHA last year") == []


@pytest.mark.parametrize("line,suffix,expected", [
    ("\t\t\ttls.TLS_RSA_WITH_AES_128_CBC_SHA,", ".go", ["TLS_RSA_WITH_AES_128_CBC_SHA"]),
    ('SSL_CTX_set_cipher_list(ctx, "AES256-SHA:ECDHE-RSA-AES128-GCM-SHA256");', ".c",
     ["TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]),
    ('engine.setEnabledCipherSuites(new String[] {"TLS_RSA_WITH_AES_128_CBC_SHA"});', ".java", ["TLS_RSA_WITH_AES_128_CBC_SHA"]),
    ('            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",', ".java", ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]),
    ('ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:!aNULL")', ".py", ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]),
    ("  ciphers: 'ECDHE-RSA-AES128-GCM-SHA256',", ".js", ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]),
])
def test_suites_in_source_code(line, suffix, expected):
    assert fams(line, suffix) == expected


@pytest.mark.parametrize("line,suffix", [
    ('log.Printf("negotiated %s", "TLS_RSA_WITH_AES_128_CBC_SHA")', ".go"),             # a log line
    ('String label = "TLS_RSA_WITH_AES_128_CBC_SHA";', ".java"),                          # a string nothing hands to TLS
    ("enum SuiteLabel { TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 }", ".java"),   # somebody's enum
    ("const TLS_RSA_WITH_AES_128_CBC_SHA = 0x2f;", ".ts"),                                # somebody's constant
    ("fmt.Println(tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256))", ".go"),              # printing a name
])
def test_names_that_are_not_configuration(line, suffix):
    assert fams(line, suffix) == []


@pytest.mark.parametrize("line,suffix,expected", [
    ("SSLProtocol -all +TLSv1.1 +TLSv1.2", ".conf", ["TLS-1.1", "TLS-1.2"]),
    ("SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1", ".conf", []),                              # everything named is turned off
    ("enabled-protocols: TLSv1.1,TLSv1.2", ".yml", ["TLS-1.1", "TLS-1.2"]),
    ("ssl-default-bind-options ssl-min-ver TLSv1.1 no-tls-tickets", ".cfg", ["TLS-1.1"]),
    ("ssl-default-bind-options no-tlsv10 no-tlsv11", ".cfg", []),
    ("MinProtocol = TLSv1", ".cnf", ["TLS-1.0"]),
    ("\t\tMinVersion: tls.VersionTLS10,", ".go", ["TLS-1.0"]),
    ("SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);", ".c", ["TLS-1.1"]),
    ("SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);", ".c", []),
    ("ctx.minimum_version = ssl.TLSVersion.TLSv1_2", ".py", ["TLS-1.2"]),
    ("handler.SslProtocols = SslProtocols.Tls11;", ".cs", ["TLS-1.1"]),
])
def test_protocol_versions(line, suffix, expected):
    assert fams(line, suffix) == expected


def test_statuses():
    assert tls.suite_status("TLS_RSA_WITH_3DES_EDE_CBC_SHA")[1] is True            # weak today
    assert tls.suite_status("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")[0].value == "vulnerable"   # key exchange falls to Shor
    assert tls.suite_status("TLS_AES_256_GCM_SHA384")[0].value == "safe_symmetric"
    assert tls.version_status("TLS-1.1")[1] is True and tls.version_status("TLS-1.3")[1] is False


def test_end_to_end_each_suite_is_a_finding_and_a_protocol_asset(tmp_path):
    (tmp_path / "site.conf").write_text(textwrap.dedent("""
        server {
            listen 443 ssl;
            ssl_protocols TLSv1.1 TLSv1.2;
            # ssl_ciphers RC4-SHA;
            ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:DES-CBC3-SHA;
        }
    """))
    found = {(f.family, f.role) for f in scan_path(tmp_path)}
    assert ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "cipher-suite") in found
    assert ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "cipher-suite") in found
    assert ("TLS-1.1", "protocol") in found
    assert not any(fam == "TLS_RSA_WITH_RC4_128_SHA" for fam, _ in found)             # the commented-out line

    from qci_pqc.models import Inventory
    from qci_pqc.report import to_cyclonedx
    comps = {c["name"]: c for c in to_cyclonedx(Inventory(project="t", findings=list(scan_path(tmp_path))))["components"]}
    suite = comps["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]["cryptoProperties"]
    assert suite["assetType"] == "protocol"
    assert suite["protocolProperties"]["cipherSuites"] == [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}]
    assert "oid" not in suite
    version = comps["TLS-1.1"]["cryptoProperties"]
    assert version == {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "TLSv1.1"}}
