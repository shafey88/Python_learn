import argparse
from scapy.all import *


def go_scan(adr):
    broadcast = scapy.all.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.all.ARP(pdst=adr)
    answered_list = scapy.all.src(broadcast, timeout=1, verbose=False)[0]
    ip_list = []
    for element in answered_list:
        current_ip_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        ip_list.append(current_ip_dict)
        return ip_list


def print_scan(ip_list):
    print('IP-Adress\t\t\tMac-Adress\n------------------')
    for element in ip_list:
        print(element['ip'] + element['mac'])


def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--range', dest='range', help='IP range')
    options = parser.parse_args()
    return options


ip = get_options()
print_scan(go_scan(ip.range))
