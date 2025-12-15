from scapy.all import *
import mac_vendor_lookup
import dpkt

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
        raise NotImplementedError 
    def get_macs(self): 
        """returns a list of MAC addresses (strings) that appear in 
the pcap""" 
        raise NotImplementedError 
    def get_info_by_mac(self, mac): 
        """returns a dict with all information about the device with 
given MAC address""" 
        raise NotImplementedError 
    def get_info_by_ip(self, ip): 
        """returns a dict with all information about the device with 
given IP address""" 
        raise NotImplementedError 
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
                device_dict["MAC"] = mac
                device_dict["IP"] = ip
                device_dict["VENDOR"] = self.vendor_lookupper.lookup(mac)
            devices_list.append(device_dict)
        return devices_list
    def __repr__(self): 
        raise NotImplementedError 
    def __str__(self): 
        raise NotImplementedError 
