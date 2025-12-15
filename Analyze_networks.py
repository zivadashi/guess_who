from scapy.all import *
import mac_vendor_lookup
import Analyzer_helper
from Analyzer_helper import OS

class AnalyzeNetwork: 
    def __init__(self, pcap_path): 
        """ 
        pcap_path (string): path to a pcap file 
        """ 
        self.pcap_path = pcap_path
        self.vendor_lookupper = mac_vendor_lookup.MacLookup()
    def get_ips(self): 
        """returns a list of ip addresses (strings) that appear in 
        the pcap""" 
        ip_list = []
        packets = rdpcap(self.pcap_path)
        for pkt in packets:
            ip = ""
            if pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                ip = arp_layer.psrc
            elif pkt.haslayer(IP):
                ip = pkt[IP].src
            if (ip not in ip_list and ip != ""):
                ip_list.append(ip)
        return ip_list
    def get_macs(self): 
        """returns a list of MAC addresses (strings) that appear in 
        the pcap"""
        mac_list = []
        packets = rdpcap(self.pcap_path)
        for pkt in packets:
            mac = ""
            if pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                mac = arp_layer.hwsrc
            elif pkt.haslayer(Ether):
                mac = pkt[Ether].src
            if (mac not in mac_list and mac != ""):
                mac_list.append(mac)
        return mac_list
    def get_info_by_mac(self, mac): 
        """returns a dict with all information about the device with 
        given MAC address""" 
        devices_list = self.get_info()
        for device in devices_list:
            if device["MAC"] == mac:
                return device
    def get_info_by_ip(self, ip): 
        """returns a dict with all information about the device with 
        given IP address""" 
        devices_list = self.get_info()
        for device in devices_list:
            if device["IP"] == ip:
                return device
    def get_info(self): 
        """returns a list of dicts with information about every 
        device in the pcap""" 
        devices_list = []
        packets = rdpcap(self.pcap_path)
        for pkt in packets:
            device_dict = {}
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                # arp reply
                arp_layer = pkt[ARP]
                ip = arp_layer.psrc
                mac = arp_layer.hwsrc
                Analyzer_helper.add_data_to_device_dict(device_dict, ip, mac, self.vendor_lookupper.lookup)
            elif pkt.haslayer(IP):
                ip = pkt[IP].src
                mac = pkt[Ether].src
                Analyzer_helper.add_data_to_device_dict(device_dict, ip, mac, self.vendor_lookupper.lookup)
            if (device_dict not in devices_list and device_dict != {}):
                devices_list.append(device_dict)
        return devices_list
    def guess_os(self, device_info):
        """returns assumed operating system of a device""" 
        target_ip = device_info["IP"]
        packets = rdpcap(self.pcap_path)
        possible_os = [True] * (len(OS) + 1)
        for pkt in packets:
            if pkt.haslayer(IP):
                if pkt[IP].src == target_ip:
                    # we found a packet that was sent from the target
                    if pkt.haslayer(ICMP):
                        icmp_layer = pkt[ICMP]
                        data_size = len(icmp_layer.payload)
                        if data_size != 32:
                            possible_os[OS.WINDOWS.value] = False     
                        if data_size != 56:
                            possible_os[OS.UNIX.value] = False
                            possible_os[OS.SOLARIS.value] = False
                            possible_os[OS.AIX.value] = False
                        if data_size != 100:
                            possible_os[OS.CISCO_ROUTER.value] = False               
                    
                    if "DF" in pkt[IP].flags:
                        possible_os[OS.WINDOWS.value] = False     
                        possible_os[OS.SOLARIS.value] = False
                        possible_os[OS.CISCO_ROUTER.value] = False               
                    else:
                        possible_os[OS.UNIX.value] = False
                        possible_os[OS.AIX.value] = False
                        
                    ttl = pkt[IP].ttl
                    if ttl > 64:
                        possible_os[OS.UNIX.value] = False
                    if ttl > 128:
                        possible_os[OS.WINDOWS.value] = False

                    possible_os_strings = []
                    if (possible_os[OS.AIX.value]):
                        possible_os_strings.append(OS.AIX.name)
                    if (possible_os[OS.WINDOWS.value]):
                        possible_os_strings.append(OS.WINDOWS.name)
                    if (possible_os[OS.UNIX.value]):
                        possible_os_strings.append(OS.UNIX.name)
                    if (possible_os[OS.SOLARIS.value]):
                        possible_os_strings.append(OS.SOLARIS.name)
                    if (possible_os[OS.CISCO_ROUTER.value]):
                        possible_os_strings.append(OS.CISCO_ROUTER.name)
                    return possible_os_strings

    def __repr__(self): 
        raise NotImplementedError 
    def __str__(self): 
        raise NotImplementedError
