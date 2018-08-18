"""ida_yara.py: python script that can be used to scan data within in an IDB using Yara."""

__author__ = "Alexander Hanel"
__version__ = "1.0.0"

import idaapi
import idautils
import idc
import imp
import bisect
try:
    imp.find_module('yara')
    import yara
except ImportError:
    print "[ERROR] Yara module not installed."
    print "Try something like... x64-python-path\python.exe -m pip install yara-python"
    

SEARCH_UP = 512  # modified 0 & 0 is still zero
SEARCH_DOWN = 1
SEARCH_NEXT = 2
SEARCH_CASE = 4
SEARCH_REGEX = 8
SEARCH_NOBRK = 16
SEARCH_NOSHOW = 32
SEARCH_UNICODE = 64
SEARCH_IDENT = 128
SEARCH_BRK = 256

# ida_search variables
g_memory = None


def yara_find_text(start_ea, y, x, ustr, sflag=0):
    """
    Search IDB data for text or regex
    :param start_ea: start address to search from
    :param y: IDA arg (ignored) pass 0
    :param x: IDA arg (ignored) pass 0
    :param ustr: search string
    :param sflag: IDA search flags
    :return: returns match offsets
    """
    _check_mem()
    yara_sig = _init_signature("text", ustr, sflag)
    offset_matches = _search(yara_sig)
    return _parse_offsets(start_ea, offset_matches, sflag)


def yara_find_binary(start_ea, ubinstr, radix=16, sflag=0):
    """
    Search IDB data for binary pattern
    :param start_ea: start address to search from
    :param ubinstr: search string
    :param radix: IDA arg (ignored) pass 0
    :param sflag: IDA search flags
    :return: returns match offsets
    """
    _check_mem()
    yara_sig = _init_signature("binary", ubinstr, sflag)
    offset_matches = _search(yara_sig)
    return _parse_offsets(start_ea, offset_matches, sflag)


def _parse_offsets(start_ea, values, sflag):
    """
    parse offset using search flags.
    If no sflags return all matches
    SEARCH_UP = search up return single match
    SEARCH_DOWN = search down return single match
    SEARCH_UP|SEARCH_NEXT = return all up from ea with the order being closest to furthest
    SEARCH_DOWN|SEARCH_DOWN = return all down from ea
    SEARCH_DOWN = same as SEARCH_DOWN
    :param start_ea: start address
    :param values: list of yara offset matches
    :param sflag: IDA search flags
    :return: match offsets spliced using sflag
    """
    if SEARCH_UP & sflag:
        up_index = bisect.bisect_left(values, start_ea)
        if SEARCH_NEXT & sflag:
            temp = values[0:up_index][::-1]
            return temp
        else:
            return values[up_index]
    if SEARCH_DOWN & sflag:
        down_index = bisect.bisect_left(values, start_ea)
        if SEARCH_NEXT & sflag:
            return values[down_index:]
        else:
            return values[down_index]
    if SEARCH_NEXT & sflag:
        down_index = bisect.bisect_left(values, start_ea)
        return values[down_index]
    return values


def _search(signature):
    """
    searches memory copied from an IDB using yara
    :param signature:
    :return:
    """
    global g_memory
    # get memory
    _memory, offsets = g_memory
    # compiled yara rules
    status, rules = _yara_compile(signature)
    if not status:
        return
        # yara search
    values = list()
    matches = rules.match(data=_memory)
    if not matches:
        return False, None
    for rule_match in matches:
        for match in rule_match.strings:
            match_offset = match[0]
            values.append(_toVirtualAddress(match_offset, offsets))
    return values


def _yara_compile(signature):
    """
    compiles yara signature
    :param signature: string of yara signature
    :return:  status, compiled rule
    """
    try:
        rules = yara.compile(source=signature)
    except Exception as e:
        print "ERROR: Cannot compile Yara rule %s" % e
        return False, None
    return True, rules


def _get_memory():
    """
    stolen from Dan aka @push_pnx
    copies bytes from IDB into memory that yara scans
    :return:
    """
    result = ""
    segments_starts = [ea for ea in idautils.Segments()]
    offsets = []
    start_len = 0
    for start in segments_starts:
        end = idc.get_segm_end(start)
        for ea in xrange(start, end):
            result += chr(idc.Byte(ea))
        offsets.append((start, start_len, len(result)))
        start_len = len(result)
    return result, offsets


def _toVirtualAddress(offset, segments):
    """
    stolen from Dan aka @push_pnx
    :param offset:
    :param segments:
    :return: returns virtual address
    """
    va_offset = 0
    for seg in segments:
        if seg[1] <= offset < seg[2]:
            va_offset = seg[0] + (offset - seg[1])
    return va_offset


def _init_signature(sig_type, pattern, sflag):
    """

    :param sig_type: string of "text" or "binary"
    :param pattern: search pattern of bytes, text or regex
    :param sflag: ida's search flags
    :return:
    """
    # print warning about ignored ida sflags
    if SEARCH_NOBRK & sflag:
        print "INFO: SEARCH_NOBRK flag is being ignored."
    if SEARCH_NOSHOW & sflag:
        print "INFO: SEARCH_NOSHOW flag is being ignored."
    if SEARCH_IDENT & sflag:
        print "INFO: SEARCH_IDENT flag is being ignored."
    if SEARCH_BRK & sflag:
        print "INFO: SEARCH_BRK flag is being ignored."
    # create regex signature
    if SEARCH_REGEX & sflag:
        signature = "/%s/" % pattern
        if SEARCH_CASE & sflag:
            # ida is not case sensitive by default but yara is
            pass
        else:
            signature += " nocase"
        if SEARCH_UNICODE & sflag:
            signature += " wide"
    elif sig_type == "binary":
        signature = "{ %s }" % pattern
    elif sig_type == "text" and (SEARCH_REGEX & sflag) == False:
        signature = '"%s"' % pattern
        if SEARCH_CASE & sflag:
            pass
        else:
            signature += " nocase"
        if SEARCH_UNICODE & sflag:
            signature += " wide"
    yara_rule = """
rule a : b
{
    strings:
        $a = %s
    condition:
        $a 
}
""" % signature
    return yara_rule


def reload_yara_mem():
    """reloads bytes in idb into memory scanned by yara"""
    global g_memory
    g_memory = _get_memory()

def _check_mem():
    global g_memory
    if not g_memory:
        print "Sorry for the wait..."
        print "Loading binary data from IDB into searchable memory for Yara..."
        g_memory = _get_memory()
        print "Execute reload_yara_mem() if the IDB has been modified."
        print "Finished."
