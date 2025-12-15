import Analyze_networks

def main():
    analyzer = Analyze_networks.AnalyzeNetwork("pcap-00.pcapng")
    
    lst = analyzer.get_info()
    print(lst)

    lst = analyzer.get_ips()
    print(lst)

    lst = analyzer.get_macs()
    print(lst)

    lst = analyzer.get_info_by_ip("172.17.174.113")
    print(lst)

    lst = analyzer.get_info_by_mac("00:1c:7f:bf:cb:bd")
    print(lst)


if __name__ == "__main__":
    main()