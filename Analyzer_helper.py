from enum import Enum, auto

class OS(Enum):
    UNIX = auto()
    WINDOWS = auto()
    SOLARIS = auto()
    AIX = auto()
    CISCO_ROUTER = auto()

def add_data_to_device_dict(device_dict, ip, mac, lookup_func):
    device_dict["IP"] = ip
    device_dict["MAC"] = mac
    device_dict["VENDOR"] = lookup_func(mac)