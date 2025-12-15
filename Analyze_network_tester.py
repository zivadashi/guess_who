import Analyze_networks

def main():
    analyzer = Analyze_networks.AnalyzeNetwork("pcap-00.pcapng")
    lst = analyzer.get_info()
    print(lst)


if __name__ == "__main__":
    main()