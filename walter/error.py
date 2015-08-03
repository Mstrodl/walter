# -*- coing: utf-8 -*-
# error.py -- walter error codes

import sys

err_codes = {
    # 0xx -- connection errors
    # 1xx -- client errors
    # 2xx -- server errors
    # 3xx -- diffie hellman key exchange errors
    # 4xx -- internal errors
    # 5xx -- crypto errors
    # 999 -- special error
    'SocketError': 001,
    'DH_NValid_PA': 301,
    'DH_NValid_PB': 302,
    'DH_NValid_DIFFIE': 303,
    'DH_NValid_YD': 304,
    
}

def err(err_code, comment=False):
    if not comment:
        comment = ''
    if isinstance(err_code, str):
        try:
            code = err_codes[err_code]
        except KeyError:
            code = 999
    else:
        code = err_code
    sys.stderr.write('Walter Error!\n')
    sys.stderr.write('Error Code: %d\n' % code)
    sys.stderr.write('Error Name: %s\n' % err_code)
    sys.stderr.write('Error COMM: %s\n' % comment)

