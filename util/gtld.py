from util.gtld_map import tldMap
from datetime import datetime
def IsInTLDMap(label):
    label = label.lower()
    try:
        ok = tldMap[label]
        return True
    except KeyError:
        return False
# Valid determines if the provided `when` time is within the GTLDPeriod for the
# gTLD. E.g. whether a certificate issued at `when` with a subject identifier
# using the specified gTLD can be considered a valid use of the gTLD.
def valid(tld,when):
    notBefore = datetime.strptime(tld["DelegationDate"],"%Y-%m-%d")
#NOTE: We can throw away the errors from time.Parse in this function because
#the zlint-gtld-update command only writes entries to the generated gTLD map
#after the dates have been verified as parseable   
    if when < notBefore:
        return False
# The removal date may be empty. We only need to check `when` against the
# removal when it isn't empty
    if tld["RemovalDate"] !="":
        notAfter = datetime.strptime(tld["RemovalDate"],"%Y-%m-%d")
        if when > notAfter:
            return False
    
    return True
#HasValidTLD checks that a domain ends in a valid TLD that was delegated in
#the root DNS at the time specified.
def HasValidTLD(domain,when):
    labels = domain.lower().split(".")
    rightlabel = labels[-1]
    # if the rightmost label is not present in the tldMap, it isn't valid and
	# never was.
    try:
        item=tldMap[rightlabel]
        # Otherwise the TLD exists, and was a valid TLD delegated in the root DNS
	    # at the time of the given date.
        if(valid(item,when)):
            return True
        else:
        # If the TLD exists but the date is outside of the gTLD's validity period
		# then it is not a valid TLD.
            return False
    except KeyError:
        return False

