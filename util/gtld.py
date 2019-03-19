from util.gtld_map import tldMap

def IsInTLDMap(label):
    label = label.lower()
    try:
        ok = tldMap[label]
        return True
    except KeyError:
        return False