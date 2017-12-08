'''
    RTF Cleaner, tries to extract URL from CVE-2017-0199 & CVE-2017-8759 samples
    by Jacob Soo (@_jsoo_)
    
    There are some samples not covered yet.
    
    Hashes for samples:
    e1d917b5580a4cad164449a163a4085f4e770471be89e960c43da1528fff1e65
    0b4ef455e385b750d9f90749f1467eaf00e46e8d6c2885c260e1b78211a51684
    84d36375954fdbcc5ba17cc1370327d42ad1b5255193484416ac7366cc33b234
    61b4ef77bc642a616a201dd5b1cd3c8c406d3fec06d84dd65c15c1f29e2e9e33
    73a40ef3417958bbfa8522234816bbd58614efc423dce92d597bbaddfe20b424
    9df5a8822439dad36fefa88ea53e53e5b9d213ec3198e3e9dc1e42f95c063b78
    27854097d2d866748c597af698cf4206d9fc7258ad1c9cbe6a70471d0857e5a9
    3ce564e8c9d257f315e9e95e443038844bac7ae6fb53807d2224dbf3b39520b4
    017c32bf75366e7de7905ff95615d79ccc102e38ec660b0245f80103b6872897
    c67970d3ad23d9d721c7ee9e1131d484a5bad6e781702bf297101bace1188e1a
    97998fcfd1a7b7adbb3aaea6b7f02bfd6d9d0c9e6bc6e8704a6d941008fd7d62
    d15d65b16afdba3d4060a978e8a75e3067ced039e0b0ea651a1fe5fa106f5b35
    cb2be36ad0b3ca9b2797d3d691a86947d1bb2a78c2dc6ca96b5960c254337d1a
'''

__description__ = 'RTF Cleaner, tries to extract URL from CVE-2017-0199 & CVE-2017-8759 samples'
__author__ = 'Jacob Soo'
__version__ = '0.1'
__date__ = '04/07/2017'

import sys, os, re
import string

#---------------------------------------------------
# _log : Prints out logs for debug purposes
#---------------------------------------------------
def _log(szString):
    print(szString)
    
def main(szFileName):
    hFile = open(szFileName,'r')
    szContents = hFile.read()
    regex_filter = [r'\{\\pntxta*([^}]*?)\}', r'\{\\lchars*([^}]*?)\}', r'\{\\\*\\aftncn\s\\pard\s\{*([^}]*?)\}\}', r'\{\\linkval*([^}]*?)\}', r'\{\\footer*([^}]*?)\}', r'\{\\mopEmu*([^}]*?)\}', r'\{\\\*\\ab', r'\\par', r'\n', r'\r', r'\t']
    for regex in regex_filter:
        szContents = szFilterText(szContents, regex)
    findURL(szContents)
    hFile.close()

def szFilterText(szContents, regex):
    szContents = re.sub(regex, '', szContents)
    return szContents

def filter_non_printable(str):
    return ''.join([c for c in str if ord(c) > 35 and ord(c) <127])

def remove_non_hex(s):
    tmp = ""
    hex_digits = set("0123456789abcdef")
    for char in s:
        if (char in hex_digits):
            tmp += str(char)
    return tmp

def findURL(textToDecode):
    # Debug
    #print(textToDecode)
    # EndDebug
    textToDecode = szFilterText(textToDecode, '\s')
    matchObj = re.findall(r'\{\\[\*|\.]\\objdata([a-z0-9]+)', textToDecode.lower())
    szHexFilter =  matchObj[0]
    # Debug
    #print(matchObj)
    # EndDebug
    
    regex_filter = [r'\s', r'\{', r'\*', r'\}', r'\\']
    for regex in regex_filter:
        szHexFilter = szFilterText(szHexFilter, regex)
    # Debug
    #print(szHexFilter)
    # EndDebug
    if len(szHexFilter) % 2 != 0:
        szHexFilter += '0'
    finalSanitised = filter_non_printable(szHexFilter.decode('hex')).lower()
    # Debug
    #print(finalSanitised)
    # EndDebug
    try:
        regExForHex = r'(http|https)\:.*?\.(hta|png|doc|xls|txt|exe)'
        matchObj = re.search(regExForHex, finalSanitised, re.DOTALL|re.UNICODE)
        if matchObj is not None:
            szHexFilter = matchObj.group()
            _log("[+] Possible URL : %s" % szHexFilter)
        else:
            regExForHex = r'cmd\/cstart\\\\.*?\.(hta|png|doc|xls|txt|exe)\&'
            matchObj = re.search(regExForHex, finalSanitised, re.DOTALL|re.UNICODE)
            szHexFilter = matchObj.group()
            _log("[+] Possible URL : %s" % szHexFilter)
    except:
        regExForHex = r'(http|https)\:[\w|\W]+\;'
        matchObj = re.search(regExForHex, finalSanitised, re.DOTALL|re.UNICODE)
        szHexFilter = matchObj.group(0)
        _log("[+] Possible URL : %s" % szHexFilter)

if __name__ == '__main__':
    if (len(sys.argv) < 2):
        _log("[+] Usage: %s [Path_To_RTF]" % sys.argv[0])
        sys.exit(0)
    else:
        _log("[+] Cleaning %s" % sys.argv[1])
        main(sys.argv[1])