import ipaddress
import subprocess

from katti import jc


def execute_dig_cmd(request_str: str, record_type: str, name_server: str | None):
    if name_server:
        cmd_output = subprocess.check_output(['dig', f'@{name_server}',  request_str, record_type], text=True, timeout=60)
    else:
        cmd_output = subprocess.check_output(['dig', request_str, record_type], text=True, timeout=60)
    return jc.parse('dig', cmd_output)


def execute_dig_cmd_with_reverse(request_str: str, record_type: str, name_server: str | None):
    if name_server:
        cmd_output = subprocess.check_output(['dig', f'@{name_server}', '-x', request_str, record_type], text=True, timeout=60)
    else:
        cmd_output = subprocess.check_output(['dig', '-x', request_str, record_type], text=True, timeout=60)
    return jc.parse('dig', cmd_output)



def reverse_ip(ip):
    try:
        ip = ipaddress.IPv4Address(ip)
    except Exception:
        ip = ipaddress.IPv6Address(ip)
    return ip.reverse_pointer.split('.in-addr.arpa')[0]
