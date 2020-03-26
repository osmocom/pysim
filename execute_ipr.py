#!/usr/bin/python3

from pySim.transport.pcsc import PcscSimLink
from pySim.utils import enc_iccid, enc_imsi

from smartcard.Exceptions import NoCardException, CardRequestTimeoutException
from smartcard.System import readers

from lark import Lark, Transformer, Token, Tree
import sys

from format_ipr import ScriptFormatIPR

class DataTransform():
    ''' Transform raw/logical input data into the format use on the SIM card,
        like encoding the PIN from '1234' -> 3132334 or IMSI encoding'''
    def transform(self, inp):
        outp = {}
        for k in inp.keys():
            f = getattr(self, 'xfrm_'+k, None)
            if f != None:
                outp[k] = f(inp[k])
            else:
                outp[k] = inp[k]
        return outp

    def xfrm_PIN(self, pin):
        ret = ''
        for c in str(pin):
            ret += '3%c' % c
        return ret
    def xfrm_PIN1(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_PIN2(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_PUK1(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_PUK2(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_ADM1(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_ADM2(self, pin):
        return self.xfrm_PIN(pin)
    def xfrm_IMSI(self, imsi):
        return enc_imsi(imsi)
    def xfrm_ICCID(self, iccid):
        # TODO: calculate luhn check digit
        return enc_iccid(iccid)


def expand_cmd_template(cmd, templates):
    ''' Take a single command, supstituting all [] template keys with data from 'template' '''
    ret = ""
    for e in cmd:
        if e[0] == 'hexstr':
            ret += e[1]
        if e[0] == 'key':
            ret += templates[e[1]]
    return ret

def match_sw(actual_sw, sw_match):
    ''' Check if actual_sw matches any of the templates given in sw_match'''
    def match_sw_single(actual_sw, match):
        match = match.lower()
        if 'x' in match:
            FIXME
        else:
            if actual_sw.lower() == match:
                return True
        return False

    if sw_match == []:
        return True

    for m in sw_match:
        if match_sw_single(actual_sw, m):
            return True

    return False


def execute_ipr_raw(s, sl, dynamic_data_raw = {}):
    """ translate a single LDR statement to IPR format. """
    if s == None:
        None
    elif s == 'reset':
        print("RESET")
        sl.reset_card()
    elif s[0] == 'rem':
        print("REM %s" % (s[1]))
    elif s[0] == 'cmd':
        d = s[1]
        req = expand_cmd_template(d['req'], dynamic_data_raw)
        rsp = d['rsp']
        print("\tREQ: %s, EXP: %s" % (req, rsp))
        (data, sw) = sl.send_apdu_raw(req)
        if not match_sw(sw, rsp):
            raise ValueError("SW %s doesn't match expected %s" % (sw, rsp))
        print("\tRSP: %s\n" % (sw))

def execute_ipr(s, sl, dynamic_data = {}):
    """ translate a single LDR statement to IPR format; optionally substitute dynamic_data. """
    xf = DataTransform()
    return execute_ipr_raw(s, sl, xf.transform(dynamic_data))


'''Dictionaries like this must be generated for each card to be programmed'''
demo_dict = {
        'PIN1': '1234',
        'PIN2': '1234',
        'PUK1': '12345678',
        'PUK2': '12345678',
        'ADM1': '11111111',

        'KIC1': '100102030405060708090a0b0c0d0e0f',
        'KID1': '101102030405060708090a0b0c0d0e0f',
        'KIK1': '102102030405060708090a0b0c0d0e0f',

        'KIC2': '200102030405060708090a0b0c0d0e0f',
        'KID2': '201102030405060708090a0b0c0d0e0f',
        'KIK2': '202102030405060708090a0b0c0d0e0f',

        'KIC3': '300102030405060708090a0b0c0d0e0f',
        'KID3': '301102030405060708090a0b0c0d0e0f',
        'KIK3': '302102030405060708090a0b0c0d0e0f',

        'ICCID': '012345678901234567',
        'IMSI': '001010123456789',
        'ACC': '0200',
        'KI': '000102030405060708090a0b0c0d0e0f',
        'OPC': '101112131415161718191a1b1c1d1e1f',
        'VERIFY_ICCID': '0001020304050608090a0b0c0d0e0f',
        }


sl = PcscSimLink(0)

infile_name = sys.argv[1]

fmt = ScriptFormatIPR()
fmt.parse_process_file(infile_name, execute_ipr, {'sl':sl, 'dynamic_data':demo_dict})
