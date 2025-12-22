import Analyze_networks

def main():
    analyzer = Analyze_networks.AnalyzeNetwork("pcap-test.pcapng")
    
    # lst = analyzer.get_info()
    # print(lst)

    # lst = analyzer.get_ips()
    # print(lst)

    # lst = analyzer.get_macs()
    # print(lst)

    # dev = analyzer.get_info_by_mac("00:0c:29:1d:1e:8f")
    # print(dev)

    devices = analyzer.get_info_by_ip("20.197.49.234")
    print(devices)

    os = analyzer.guess_os(devices[0])
    print(os)

if __name__ == "__main__":
    main()