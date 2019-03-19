import sys
sys.path.append("..")
from lints import base
from lints import lint_dnsname_contains_bare_iana_suffix
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestIANABareSuffix(unittest.TestCase):
    '''test lint_dnsname_contains_bare_iana_suffix.py'''        
    def test_IANABareSuffix(self):
        certPath ='..\\testCerts\\dnsNameContainsBareIANASuffix.pem'
        lint_dnsname_contains_bare_iana_suffix.init()
        with open(certPath, "rb") as f:
            cert=x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_dnsname_contains_bare_iana_suffix"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
