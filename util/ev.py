from cryptography.x509 import ExtensionOID,ExtensionNotFound
evoids={
    "1.3.159.1.17.1":                   True,
	"1.3.6.1.4.1.34697.2.1":            True,
	"1.3.6.1.4.1.34697.2.2":            True,
	"1.3.6.1.4.1.34697.2.3":            True,
	"1.3.6.1.4.1.34697.2.4":            True,
	"1.2.40.0.17.1.22":                 True,
	"2.16.578.1.26.1.3.3":              True,
	"1.3.6.1.4.1.17326.10.14.2.1.2":    True,
	"1.3.6.1.4.1.17326.10.8.2.1.2":     True,
	"1.3.6.1.4.1.6449.1.2.1.5.1":       True,
	"2.16.840.1.114412.2.1":            True,
	"2.16.840.1.114412.1.3.0.2":        True,
	"2.16.528.1.1001.1.1.1.12.6.1.1.1": True,
	"2.16.792.3.0.4.1.1.4":             True,
	"2.16.840.1.114028.10.1.2":         True,
	"0.4.0.2042.1.4":                   True,
	"0.4.0.2042.1.5":                   True,
	"1.3.6.1.4.1.13177.10.1.3.10":      True,
	"1.3.6.1.4.1.14370.1.6":            True,
	"1.3.6.1.4.1.4146.1.1":             True,
	"2.16.840.1.114413.1.7.23.3":       True,
	"1.3.6.1.4.1.14777.6.1.1":          True,
	"2.16.792.1.2.1.1.5.7.1.9":         True,
	"1.3.6.1.4.1.782.1.2.1.8.1":        True,
	"1.3.6.1.4.1.22234.2.5.2.3.1":      True,
	"1.3.6.1.4.1.8024.0.2.100.1.2":     True,
	"1.2.392.200091.100.721.1":         True,
	"2.16.840.1.114414.1.7.23.3":       True,
	"1.3.6.1.4.1.23223.2":              True,
	"1.3.6.1.4.1.23223.1.1.1":          True,
	"2.16.756.1.83.21.0":               True,
	"2.16.756.1.89.1.2.1.1":            True,
	"1.3.6.1.4.1.7879.13.24.1":         True,
	"2.16.840.1.113733.1.7.48.1":       True,
	"2.16.840.1.114404.1.1.2.4.1":      True,
	"2.16.840.1.113733.1.7.23.6":       True,
	"1.3.6.1.4.1.6334.1.100.1":         True,
	"2.16.840.1.114171.500.9":          True,
	"1.3.6.1.4.1.36305.2":              True,
}

#IsEV returns true if the input is a known Extended Validation OID.
def IsEV(extensions):
    try:
        policies = extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        for policy in policies:
            return evoids.get(policy.policy_identifier.dotted_string,False)
    except ExtensionNotFound:
        return False