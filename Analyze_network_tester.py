import Analyze_networks

def main():
    analyzer = Analyze_networks.AnalyzeNetwork("pcap-01.pcapng")
    
    lst = analyzer.get_info()
    print(lst)

    lst = analyzer.get_ips()
    print(lst)

    lst = analyzer.get_macs()
    print(lst)

    lst = analyzer.get_info_by_ip("172.17.174.113")
    print(lst)

    lst = analyzer.get_info_by_mac("00:0c:29:1d:1e:8f")
    print(lst)


if __name__ == "__main__":
    main()