import sys
sys.path.append("..")
from lints import base
from lints import lint_ext_san_directory_name_present
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSANDirNamePresent2(unittest.TestCase):
    '''test lint_ext_san_directory_name_present.py'''
    def test_SANDirNamePresent(self):
        certPath ='..\\testCerts\\SANRFC822Beginning.pem'
        lint_ext_san_directory_name_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_must_be_dns_or_ipaddress"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SANDirNameMissing(self):
        certPath ='..\\testCerts\\SANCaGood.pem'
        lint_ext_san_directory_name_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_must_be_dns_or_ipaddress"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

    def test_SANPartyPresent(self):
        certPath ='..\\testCerts\\SANEDIParty.pem'
        lint_ext_san_directory_name_present.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_ext_san_must_be_dns_or_ipaddress"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)
