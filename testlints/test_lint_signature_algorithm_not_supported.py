import sys
sys.path.append("..")
from lints import base
from lints import lint_signature_algorithm_not_supported
import unittest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class TestSignatureAlgorithmNotSupported(unittest.TestCase):
    '''test lint_signature_algorithm_not_supported.py'''
    def test_SignatureAlgorithmNotSupported(self):
        certPath ='..\\testCerts\\md5WithRSASignatureAlgorithm.pem'
        lint_signature_algorithm_not_supported.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_signature_algorithm_not_supported"].Execute(cert)
            self.assertEqual(base.LintStatus.Error,out.Status)

    def test_SignatureAlgorithmSHA1Supported(self):
        certPath ='..\\testCerts\\sha1WithRSASignatureAlgorithm.pem'
        lint_signature_algorithm_not_supported.init()
        with open(certPath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            out = base.Lints["e_signature_algorithm_not_supported"].Execute(cert)
            self.assertEqual(base.LintStatus.Pass,out.Status)

if __name__=="__main__":
    unittest.main(verbosity=2)