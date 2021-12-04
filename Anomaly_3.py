import sys
import argparse
import os
try:
    from scapy import *
    from scapy.all import *
except:
    os.system("pip3 install scapy")
    from scapy import *
    from scapy.all import *

try:
    import numpy as np
except:
    os.system("pip3 install numpy")
    import numpy as np

def r(n):
    return (np.random.choice(range(n)))

def ip_r():
    return(str(r(256))+"."+str(r(256))+"."+str(r(256))+"."+str(r(256)))

def p_r(a,b):
    return(np.random.choice(range(a,b)))

def Mimicry_3(args):
    m=[]
    for i in range(355):
        m.append(IP(src=args.ip_src,dst=ip_r())/TCP(sport=int(args.port_src),dport\
            =p_r(1024,65536),flags="S"))
    send(m,iface="lo")

if __name__=="__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip_src', help='Fixed IP address source for mimicry')
    parser.add_argument('-port_src', help='Fixed port source for mimicry')
    args = parser.parse_args()
    Mimicry_3(args)
    
