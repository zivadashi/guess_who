import Analyze_networks

def main():
    analyzer = Analyze_networks.AnalyzeNetwork("pcap-03.pcapng")
    
    lst = analyzer.get_info()
    print(lst)

    # lst = analyzer.get_ips()
    # print(lst)

    # lst = analyzer.get_macs()
    # print(lst)

    # dev = analyzer.get_info_by_mac("00:0c:29:1d:1e:8f")
    # print(dev)

    # dev = analyzer.get_info_by_ip("192.168.226.1")
    # print(dev)

    # os = analyzer.guess_os(dev)
    # print(os)

if __name__ == "__main__":
    main()