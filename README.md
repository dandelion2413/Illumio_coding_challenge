# Illumio_coding_challenge

Test the code by running the command:
  python Illumio.py
Both python2 and python3 work.

When constructing the Firewall object, I use 3 layers of default dict to store direction, protocol, and port respectively so that program can easily get a list of range of IP adresses by calling rules[direction][protocol][port] with O(1) constant time complexity. Since there are about 4 billion possible IPs and only 1 million rules, we can easily iterate through the returned IP address ranges to see if the packet should be accepted. To do so, I built a function ip2int to convert the IP address string to int format so that program can easily determine whether a new IP address is within the range. 

In addition, I designed an Inteval class to store the inclusive interval for IP range. Since object is mutable, even if I put the Interval object in multiple ports, there will only be one copy of referenced object in all of them and thereby, no redundant variables are stored. We can estimate how much memory is saved by calling asizeof function.
