from lints import base
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from util.time import Time
from util import ca
'''
Restrictions are defined in terms of permitted or excluded name
   subtrees.  Any name matching a restriction in the excludedSubtrees
   field is invalid regardless of information appearing in the
   permittedSubtrees.  Conforming CAs MUST mark this extension as
   critical and SHOULD NOT impose name constraints on the x400Address,
   ediPartyName, or registeredID name forms.  Conforming CAs MUST NOT
   issue certificates where name constraints is an empty sequence.  That
   is, either the permittedSubtrees field or the excludedSubtrees MUST
   be present.
'''
class nameConstraintEmpty(base.LintInterface):

    def Initialize(self):
        return 0
    
    def CheckApplies(self,c):
        return ca.IsExtInCert(c,ExtensionOID.NAME_CONSTRAINTS)

    def Execute(self,c):
        try:
            Nameconstraints = c.extensions.get_extension_for_oid(ExtensionOID.NAME_CONSTRAINTS)
            if not Nameconstraints.value.permitted_subtrees and not Nameconstraints.value.excluded_subtrees :
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Pass)
        except x509.ExtensionNotFound:
            return  base.LintResult(base.LintStatus.NA)
        except ValueError as e:
            if "At least one of permitted_subtrees and excluded_subtrees must not be None"==str(e):
                return base.LintResult(base.LintStatus.Error)
            return base.LintResult(base.LintStatus.Fatal)
def init():
    base.RegisterLint(base.Lint("e_name_constraint_empty","Conforming CAs MUST NOT issue certificates where name constraints is an empty sequence. That is, either the permittedSubtree or excludedSubtree fields must be present","RFC 5280: 4.2.1.10",base.LintSource.RFC5280,Time.RFC5280Date,nameConstraintEmpty()))