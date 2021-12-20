from optparse import OptionParser
from Crypto.Cipher import ARC4
from hashlib import sha1
from struct import *

import hexdump
import socket
import winreg
import sys
import wmi
import os
import re

tbl4 =    [ 0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c]

def mit_crc32_shift4(data, seed):
    crc = ~seed & 0xffffffff
    for byte in data:
        x = tbl4[(byte ^ crc ) & 0x0f] ^ ((byte ^ crc)  >> 4)
        crc = tbl4[x & 0x0f] ^  (x >> 4)
    
    return ~crc & 0xffffffff

def widen_string(string):
    s = string.encode('utf-16')
    if s[:2] == b'\xff\xfe':
        return s[2:]
    return s

def precalculate_reg_names(key):
    """precalculate registry names, returns a dictionary {'regname':'id'} """
    reg_names = {}
    for i in range(0,0xff):
        reg_names[hex(mit_crc32_shift4(pack('I',i), key))[2:]] = i
    return reg_names


def get_all_reg_values(reg_key):
    """gets all qakbot registry value"""
    regs = {}
    i = 0
    while True:
        try:
            vname, value, vtype = winreg.EnumValue(reg_key, i)
            regs[vname] = value
        except WindowsError as e:
            break
        i+=1
    return regs

def get_password():
    """gets the computer name, C: drive volume serial number, and account name"""
    try:
        computer_name = socket.gethostname();
    except:
        computer_name = os.environ['COMPUTERNAME']
    for volume in wmi.WMI().Win32_LogicalDisk():
        if volume.Caption == 'C:':
            volume_serial_number = str(int(volume.VolumeSerialNumber,16))
            break
    user_account_name = os.getlogin()
    return widen_string(computer_name.upper() + volume_serial_number.upper() + user_account_name.upper())


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-r','--regpath', 
        type='string', 
        dest='registry_path',
        help="registry path where Qakbot's encrypted data is stored. (e.g. 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Efwramsn')")
    parser.add_option('-p', '--password', 
        type='string', 
        dest='password',
        help="password (optional)")
    (options, args) = parser.parse_args()

    if options.password:
        password = options.password
    else:
        password = get_password()

    if options.registry_path:
        root_match = re.match(r'^([Hh][a-zA-Z_]*?)\\(.*?)$',options.registry_path)
        if root_match:
            root = root_match.group(1)
            if root.upper() == 'HKLM' or root.upper() == 'HKEY_LOCAL_MACHINE':
                regkey = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, root_match.group(2))
            if root.upper() == 'HKCU' or root.upper() == 'HKEY_CURRENT_USER':
                regkey = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, root_match.group(2))
    else:
        print('Registry key is required')
        sys.exit(0)

    print('Using password: "%s"'%password.decode('utf-16'))
    password_hash = mit_crc32_shift4(password,0)
    all_regs = get_all_reg_values(regkey)
    precalc_regs = precalculate_reg_names(password_hash)

    for name,value in all_regs.items():
        id_seed = precalc_regs[name]
        key = pack('I',id_seed) + pack('I',password_hash)
        derived_key = sha1(key).digest()
        cipher = ARC4.new(derived_key)
        msg = cipher.decrypt(value)
        print("Registry key path: {}\n{}".format(options.registry_path+"\\"+name, hexdump.hexdump(msg, result="return")))