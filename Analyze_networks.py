from scapy.all import *
import mac_vendor_lookup
import Analyzer_helper

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
        for pkt in packets:
            if pkt.haslayer(IP):
                if pkt[IP].src == target_ip:
                    # we found a packet that was sent from the target
                    ttl = pkt[IP].ttl
                    if ttl == 64:
                        return "Unix"
                    if ttl == 128:
                        return "Windows"
                    if ttl == 254:
                        return "Solaris, AIX"
                    if ttl == 255:
                        return "AIX, BSDI, Solaris, Cisco router"
    def __repr__(self): 
        raise NotImplementedError 
    def __str__(self): 
        raise NotImplementedError
