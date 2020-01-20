# Import libraries and install those which need to be installed
# before importing
# The installation process here is for Ubuntu
import socket
import struct
import os
import time
import sys
from threading import Thread, RLock
import multiprocessing as mp
from util import timeout
prog = sys.modules['__main__']

verrou = RLock()
Lock_Stack  = RLock()

try:
    from scapy import *
    from scapy.utils import *
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
except:
    os.system("pip3 install scapy")
    from scapy import *
    from scapy.utils import *
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP

try:
    import itertools
except:
    os.system("pip3 install itertools")
    import itertools
import gc

try:
    import numpy as np
except:
    os.system("pip3 install numpy")
    import numpy as np

try:
    from sklearn.cluster import KMeans
    kmeans = KMeans(n_clusters=2, init='k-means++', max_iter=300, n_init=10, random_state=0)
except:
    os.system("pip3 install sklearn")
    from sklearn.cluster import KMeans
    kmeans = KMeans(n_clusters=2, init='k-means++', max_iter=300, n_init=10, random_state=0)

try:
    import matplotlib.pyplot as plt
except:
    os.system("pip3 install matplotlib")
    import matplotlib.pyplot as plt

import warnings
from sklearn.exceptions import ConvergenceWarning
warnings.simplefilter("ignore")

@timeout(seconds = 0.1)
def Record(s):
    '''Record packets with timeout exception'''
    return (s.recvfrom(65565)[0])

def Verify(ether_pkt):
    '''Verify if a packet is useful (IP and TCP/UDP)'''
    ether_pkt = Ether(ether_pkt)
    t = ether_pkt.summary()
    if "IP" not in t or "IPv6" in t:
        #disregard non-IP packets
        return

    if ("UDP" not in t and "TCP" not in t) or ("error" in t):
        # disregard non-(UDP and TCP) packets
        return

    ip_pkt = ether_pkt[IP]
    if "TCP" in t:
        #Treat TCP packet           
        tcp_pkt = ip_pkt[TCP]
        return(["tcp",str(ip_pkt.src),str(ip_pkt.dst),int(tcp_pkt.sport),int(tcp_pkt.dport)])

    if "UDP" in t:
        #Treat UDP packet   
        udp_pkt = ip_pkt[UDP]
        return(["udp",str(ip_pkt.src),str(ip_pkt.dst),int(udp_pkt.sport),int(udp_pkt.dport)])

class Clean(Thread):
    """Process Verify useful packets"""
    def __init__(self):
        Thread.__init__(self)
        self.Verify = Verify

    def run(self):
        while prog.End!=1:
            if prog.file:
                with verrou:
                    File = prog.file.pop(0)
                Sortie = []
                if not File:
                    with Lock_Stack:
                        prog.Stack.append(Sortie)
                    time.sleep(0.01)
                    continue
                p = mp.Pool((len(File)>=30)*30 + (len(File)<30)*len(File))
                for out in p.imap_unordered(self.Verify,File):
                    if out != None:
                        Sortie.append(out)
                p.terminate()
                with Lock_Stack:
                    prog.Stack.append(Sortie)
                time.sleep(0.01)

class Principal(Thread):
    """Process treating flows per time interval and Deciding about anomalcy"""
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        prog.comp=prog.N+2
        time.sleep(2*prog.N)
        Hist=[]
        Div=[]
        Copy=[]
        i=1
        while prog.End!=1:
            Time = time.time()
            if len(Copy)>=2*prog.N+2:
                prog.comp+=1                     
                Div_Near=Div.copy()
                Div_Curr=(Div_Near.pop(prog.N)+Div_Near.pop(prog.N))/2.0
                
                prog.Stack.pop(0)
                if prog.comp==prog.N+3 and i==1:
                    i = 0
                    print("Done\n")
                    prog.comp = 1

                if prog.Previous_Decision==[] or prog.Previous_Decision[-1]==False:
                    if not Is_Suspicious(Div_Curr, Div_Near):
                        prog.Previous_Decision.append(False)
                        print("Time interval %d : NOT SUSPICIOUS"%(prog.comp))
                        print("")
                        Copy.pop(0)
                        Hist.pop(0)
                        Div.pop(0)
                        if time.time()-Time<0.9:     
                            if len(Copy)<len(prog.Stack):
                                Copy.append(prog.Stack[len(Copy)])
                                Hist.append(prob_hist(Copy[-1],prog.n))
                                if len(Copy)>1:
                                    new = div_Current(Hist[len(Div)+1],Hist[len(Div)])
                                    Div.append(new)
                                    prog.Divergences.append(new)
                        continue

                    Flows_Curr=Copy[prog.N+1]
                    Flows_Prev=Copy[prog.N]
                    Suspect_Flows(Flows_Curr,Flows_Prev,prog.n,prog.TopN)
                    print("")
                    Copy.pop(0)
                    Hist.pop(0)
                    Div.pop(0)
                    if time.time()-Time<0.9:     
                        if len(Copy)<len(prog.Stack):
                            Copy.append(prog.Stack[len(Copy)])
                            Hist.append(prob_hist(Copy[-1],prog.n))
                            if len(Copy)>1:
                                new = div_Current(Hist[len(Div)+1],Hist[len(Div)])
                                Div.append(new)
                                prog.Divergences.append(new)
                else:
                    if not Is_Suspicious(Div_Curr, Div_Near):
                        Flows_Curr=Copy[prog.N+1]
                        Flows_Prev=Copy[prog.N]
                        Suspect_Flows(Flows_Curr,Flows_Prev,prog.n,prog.TopN)
                        print("")
                        Copy.pop(0)
                        Hist.pop(0)
                        Div.pop(0)
                        if time.time()-Time<0.9:     
                            if len(Copy)<len(prog.Stack):
                                Copy.append(prog.Stack[len(Copy)])
                                Hist.append(prob_hist(Copy[-1],prog.n))
                                if len(Copy)>1:
                                    new = div_Current(Hist[len(Div)+1],Hist[len(Div)])
                                    Div.append(new)
                                    prog.Divergences.append(new)
                        continue

                    prog.Previous_Decision.append(False)
                    print("Time interval %d : Ambiguous"%(prog.comp))
                    print("")
                    Copy.pop(0)
                    Hist.pop(0)
                    Div.pop(0)
                    if time.time()-Time<0.9:     
                        if len(Copy)<len(prog.Stack):
                            Copy.append(prog.Stack[len(Copy)])
                            Hist.append(prob_hist(Copy[-1],prog.n))
                            if len(Copy)>1:
                                new = div_Current(Hist[len(Div)+1],Hist[len(Div)])
                                Div.append(new)
                                prog.Divergences.append(new)
            else:
                with Lock_Stack:
                    if len(Copy)<len(prog.Stack):
                        Copy.append(prog.Stack[len(Copy)])
                        Hist.append(prob_hist(Copy[-1],prog.n))
                        if len(Copy)>1:
                            new = div_Current(Hist[len(Div)+1],Hist[len(Div)])
                            Div.append(new)
                            prog.Divergences.append(new)
                time.sleep(0.0001)

            

def Find_Class(p_src,p_dst):
    '''Find the class of port pair aggregation for a given Port Source and Destination'''
    c=int(p_src/256)*256
    d=c+255
    e=int(p_dst/256)*256
    f=e+255
    if c<e:
        return([[c,d],[e,f]])
    return([[e,f],[c,d]])

def Count(Flows,n):
    '''Count flows per class of port pair aggregation'''
    C=np.zeros(n,int)
    for i in range(len(Flows)):
        P_src=Flows[i][3]
        P_dst=Flows[i][4]
        if P_src > 1023 and P_dst > 1023:
            continue
        if P_src <= 1023 and P_dst <= 1023:
            continue
        Range=Find_Class(P_src,P_dst)
        try:
            ind=prog.G.index(Range)
            C[ind]+=1
        except Exception as e:
            pass
    return(C)

def prob_hist(Flows,n):
    '''Compute the Histogram for a given time interval flow'''
    H=np.zeros(n)
    C=Count(Flows,n)
    T=sum(C)
    if T==0:
        return (H)
    for i in range(n):
        H[i]=float(C[i])/T
    #print(sum(H))
    return(H)

def div_KL(P,Q):
    '''Compute the Kullback-Leibler divergence'''
    n=len(P)
    div=0
    for i in range(n):
        if P[i]==0:
            continue
        den=Q[i]
        if den==0:
            den=0.0001
        div+=P[i]*np.log(P[i]/den)
    return (div)

def div_Current(P,Q):
    '''Compute the divergence between the current and the previous time intervals'''
    if sum(P) == 0:
        return 0
    return(div_KL(P,Q)+div_KL(Q,P))

def Is_Suspicious(Div_Curr, Div_Near):
    '''Verify if the time interval is suspicious'''
    if Div_Curr==0 or Div_Curr<=min(Div_Near):
        return False
    if len(Div_Near)==1:
        if Div_Near[0]>=Div_Curr:
            return False
        return True
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            kmeans.fit(np.array(Div_Near+[Div_Curr]).reshape(-1, 1))
            k = kmeans.labels_
            if  list(k).count(k[-1])<((len(k)+1)//2):
                centers = kmeans.cluster_centers_
                if centers[k[-1]][0] < centers[(k[-1]+1)%2][0]:
                    return False
                return True
            Div_Near = list(np.array(Div_Near+[Div_Curr])[k==k[-1]])
            Div_Near.pop()
            return Is_Suspicious(Div_Curr, Div_Near)
    except Exception as e:
        print(e)


def div(P,Q):
    '''Compute pi*log(pi/qi)'''
    if P==0:
        return (0)
    den=Q
    if den==0:
        den=0.0001
    return (P*np.log(P/den))

def Suspect_Flows(Flows_Curr,Flows_Prev,n,TopN):
    '''Collect Mimicry anomaly flows once the time interval is suspicious'''
    P=prob_hist(Flows_Curr,n)
    Q=prob_hist(Flows_Prev,n)
    susp_Gr=[]
    suspicion=[]
    for i in range(n):
        suspicion.append(div(P[i],Q[i]))
        
    susp=suspicion.copy()
    susp.sort(reverse=True)
    for i in range(TopN):
        susp_Gr.append(suspicion.index(susp[i]))
    
    C=[]
    dec = "\nNo\n"
    for i in range(len(Flows_Curr)):
        P_src  = Flows_Curr[i][3]
        P_dst  = Flows_Curr[i][4]
        if P_src > 1023 and P_dst > 1023:
            continue
        if P_src <= 1023 and P_dst <= 1023:
            continue
        Range=Find_Class(P_src,P_dst)
        ind=prog.G.index(Range)
        if ind not in susp_Gr:
            continue
            
        if Flows_Curr[i] not in Flows_Prev and \
        Flows_Curr[i] not in C:
            C.append(Flows_Curr[i])
            if Flows_Curr[i][1]=="192.185.10.22":
            	dec = "\nYES\n"
            if Flows_Curr[i] not in prog.Attacks:
                prog.Attacks.append(Flows_Curr[i])
    
    if C:
        prog.Previous_Decision.append(True)
        print("Time interval %d : \033[31mSUSPICIOUS\033[0m"%(prog.comp))
        if dec =="\nYES\n":
        	print(dec)
        print("   Mimicry flows")
        return(print(C))

    prog.Previous_Decision.append(False)
    print("Time interval %d : NOT SUSPICIOUS"%(prog.comp))

if __name__ == "__main__":
    # Initialisations
    n=1008
    TopN=5
    N=10
    Stack=[]
    file = []
    comp=0
    Previous_Decision = []
    Exp_Time = 10000   #Stopping time

    Attacks = []
    Divergences = []
    T = 0
    End = 0

    # Port pair Aggregation
    G=[]
    n=1008
    G.append([[0   , 255 ] , [1024, 1279]])
    G.append([[256 , 511 ] , [1024, 1279]])
    G.append([[512 , 767 ] , [1024, 1279]])
    G.append([[768 , 1023] , [1024, 1279]])

    print("\nPlease wait {} seconds for the system to start ...    ".format(2*N+2), end = "")

    for i in range(4,n):
        G.append([G[i%4][0],[G[i-4][1][0]+256,G[i-4][1][1]+256]])

    #Preparing packets capturing socket
    s = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

    # Run the principal and Cleaning Processes for checking
    P   = Principal()
    T   = Clean()

    # Start Processes
    T.start()
    P.start()    

    # Start Capturing packets
    # This step can not be done as a process
    # because the Record function has timeout exception to avoid waiting for packet
    # And this timeout Exception only works in the main module
    Init_Time = time.time()
    while time.time() - Init_Time <= Exp_Time:
        File = []
        Time = time.time()
        while time.time()-Time<0.999999:
            try:
                File.append(Record(prog.s))
            except Exception as e:
                pass
        with verrou:
            prog.file.append(File)

    End = 1
    plt.plot(Divergences)
    plt.show()
    
    T.join()
    P.join()

    
