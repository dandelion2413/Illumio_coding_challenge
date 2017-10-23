from collections import defaultdict
import csv
import socket
import struct

class Firewall(object):
    """
    Firewall that takes in rules and access packets that follow the rules.
    """
    def __init__(self, fw_path):
        """
        Constructor for the Firewall class. Create data member rules that 
        saves all rules from csv file in firewall path.

        Args:
            fw_path: String representing the path of csv file with firewall rules.
        """
        self.rules = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        with open(fw_path, 'r') as csvfile:
            for row in csv.reader(csvfile):
                port_range = Interval(row[2])
                interval = Interval(row[3])
                for port in range(port_range.low, port_range.high + 1):
                    self.rules[row[0]][row[1]][port].append(interval)

    def accept_packet(self, direction, protocol, port, ip_address):
        """
        Check whether a packet should be accept.

        Args:
            direction: String for packet direction. It is either inbound or outbound.
            protocol: String for packet protocol. It is either tcp or udp.
            port: Integer for port number ranging from 1 to 65535.
            ip_address: String for IPv4 address (4 octets, each in the range from 1 to 255)
        Returns:
            Boolean representing if the packet should be accept.
        """     
        return any(interval.contains(ip_address) for interval in self.rules[direction][protocol][port])

class Interval(object):
    """
    Inclusive interval for the range of IP address
    """
    def __init__(self, range_str):
        """
        Constructor for the interval class. If range_str is just an IP address, 
        set the range as [IP, IP].

        Args:
            range_str: string representation of the range of IP adddress.
        """
        index = range_str.find('-')
        if index == -1:
            self.low = self.ip2int(range_str)
            self.high = self.ip2int(range_str)
        else:
            self.low = self.ip2int(range_str[:index])
            self.high = self.ip2int(range_str[index + 1:])

    def ip2int(self, addr):
        """
        Convert IP address to integer. If addr is just an integer, return itself.

        Args:
            addr: IP address.
        Returns:
            Return the IP address in integer type.
        """
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def contains(self, addr):
        """
        Check if the IP address is between the interval.

        Args:
            addr: IP address.
        Returns:
            Boolean representing if the addr is between the interval.
        """     
        return self.low <= self.ip2int(addr) <= self.high

# Unit testing in main function. Code should pass all test cases without assertion error
if __name__ == '__main__':
    fw = Firewall('fw.csv')
    assert(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True)
    assert(fw.accept_packet("inbound", "udp", 53, "192.168.2.1") == True)
    assert(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11") == True)
    assert(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2") == False)
    assert(fw.accept_packet("inbound", "udp", 24, "52.12.48.92") == False)
    assert(fw.accept_packet("outbound", "udp", 1000, "52.12.48.92") == True)
    assert(fw.accept_packet("outbound", "tcp", 18000, "192.168.10.12") == False)
    assert(fw.accept_packet("outbound", "udp", 20000, "192.168.10.11") == False)
    assert(fw.accept_packet("inbound", "tcp", 20000, "192.168.10.11") == False)
