from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
"A certificate MUST NOT include more than one instance of a particular extension."
'''
class ExtDuplicateExtension(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        try:
            return c.version==x509.Version.v3
        except x509.InvalidVersion:
            return False
    def Execute(self,c):
        try:
            extensions=[]
            for extension in c.extensions:
                if extension.oid in extensions:
                    return base.LintResult(base.LintStatus.Error)
                else:
                    extensions.append(extension.oid)
            return base.LintResult(base.LintStatus.Pass)
        except ValueError:
            return  base.LintResult(base.LintStatus.Fatal)
        except x509.extensions.DuplicateExtension:
            return base.LintResult(base.LintStatus.Error)
def init():
    base.RegisterLint(base.Lint("e_ext_duplicate_extension","A certificate MUST NOT include more than one instance of a particular extension","RFC 5280: 4.2",base.LintSource.RFC5280,Time.RFC2459Date,ExtDuplicateExtension()))