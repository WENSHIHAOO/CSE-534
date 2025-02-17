import dpkt
tcpFlows=[]
class TCP:
    def __init__(self):
        self.sourcePort=0
        self.destinationPort=0
        self.seqNum=0
        self.ackNum=0
        self.windowSize=0
        self.flagAck=0
        self.flagSyn=0
        self.flagFin=0
        self.MSS=0
        self.timestmp=0
        self.RTT=0
        self.bufLen=0
        
class Flow:
    def __init__(self):
        self.sourcePort=0
        self.destinationPort=0
        self.totalTcp=0
        self.usefulTcp=0
        self.tripleDuplicateAck=0
        self.timeout=0
        self.lastRetransmission=0
        self.tcpArray=[]
        self.lastSeqBySenter=0
        self.add1=False
        self.frist10CongestionWin=[]
        self.last=TCP()

def resolvePcap():
    global tcpFlows
    f= open("assignment2.pcap", 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        tcp=TCP()
        flow=Flow()
        haveFlow=True
        haveFlowTcp=True
        tcp.sourcePort = buf[34] * 256 + buf[35]
        tcp.destinationPort = (buf[36] * 256) + buf[37]
        for f in tcpFlows:
            if(f.sourcePort==tcp.sourcePort and f.destinationPort==tcp.destinationPort):
                haveFlow=False
                flow = f
                break
        if(flow.sourcePort==0):
            flow.sourcePort=tcp.sourcePort
            flow.destinationPort=tcp.destinationPort
        tcp.seqNum=(buf[38] * 256 * 256 * 256) + (buf[39] * 256 * 256) + (buf[40] * 256) + buf[41]
        tcp.ackNum=(buf[42] * 256 * 256 * 256) + (buf[43] * 256 * 256) + (buf[44] * 256) + buf[45]
        ## 0x002=syn, 0x010 = ack, 0x008 = psh, 0x001=fin
        if(buf[47]%2 == 1):tcp.flagFin=1
        if((buf[47]>>4)%2 == 1):tcp.flagAck=1
        if((buf[47]>>1)%2 == 1):tcp.flagSyn=1
        if(tcp.flagSyn==1):tcp.windowSize=(buf[48] * 256) + buf[49]; tcp.MSS=(buf[56] * 256) + buf[57]
        else: tcp.windowSize=((buf[48] * 256) + buf[49])*16384; tcp.MSS=flow.tcpArray[0].MSS
        #tcp.MSS=(buf[56] * 256) + buf[57]
        tcp.timestmp=ts
        tcp.bufLen=len(buf)
        flow.totalTcp=flow.totalTcp+1
        for f in reversed(flow.tcpArray):
            if(ts-f.timestmp>0.002): break 
            if(f.seqNum==tcp.seqNum and tcp.ackNum==f.ackNum):
                if(flow.sourcePort == 80):
                    if(flow.lastRetransmission==tcp.ackNum):
                        flow.tripleDuplicateAck+=1
                    else:
                        flow.timeout+=1
                        flow.lastRetransmission=tcp.ackNum
                else:
                    if(flow.lastRetransmission==tcp.seqNum):
                        flow.tripleDuplicateAck+=1
                    else:
                        flow.timeout+=1
                        flow.lastRetransmission=tcp.seqNum
                haveFlowTcp=False
                break
        if(haveFlowTcp): flow.tcpArray.append(tcp); flow.usefulTcp=flow.usefulTcp+1
        if(haveFlow): tcpFlows.append(flow)
        #RTT and con
        if(haveFlowTcp and (tcp.sourcePort == 80)):
            for t in tcpFlows:
                if(t.sourcePort==tcp.destinationPort):
                    #con
                    if(tcp.ackNum>=t.lastSeqBySenter and len(t.frist10CongestionWin)<10):
                        for f in reversed(t.tcpArray):
                            t.last=f
                            t.lastSeqBySenter=f.seqNum
                            t.add1=True
                            break
                    #RTT and con
                    for f in reversed(t.tcpArray):
                        if(f.ackNum==tcp.seqNum and tcp.ackNum==f.seqNum):
                            # con
                            if(t.add1 and ts-t.last.timestmp >= 0.0001 and t.lastSeqBySenter>tcp.ackNum and len(t.frist10CongestionWin)<10):
                                size=t.lastSeqBySenter-tcp.ackNum
                                t.frist10CongestionWin.append(size)
                                t.add1=False
                            #RTT
                            f.RTT=ts-f.timestmp
                            break
                    break
#first 2 from sender to receiver
def first2(flow):
    print("Sequence number:",flow.tcpArray[0].seqNum,'| Ack number:',flow.tcpArray[0].ackNum, '| Receive Window size:', flow.tcpArray[0].windowSize, end="\n")
    print("Sequence number:",flow.tcpArray[1].seqNum,'| Ack number:',flow.tcpArray[1].ackNum, '| Receive Window size:', flow.tcpArray[1].windowSize, end="\n")
#throughput at the receiver
def throughput(flow):
    tput=0
    i=0
    for tcp in flow.tcpArray:
        if(tcp.RTT > 0):
            i=i+1
            tput=tput+(tcp.MSS/tcp.RTT)
    print("Throughput at",flow.destinationPort,": ",tput/i,end='\n')
#loss rate for each flow
rate=0
def lossRate(flow):
    global rate
    rate=1-((flow.usefulTcp-1)/flow.totalTcp)
    print("loss rate:",rate,end='\n')
#Estimate the average RTT, and the theoretical throughput 
def RTTAndThroughput(flow):
    RTT=0
    for tcp in flow.tcpArray:
        if(tcp.RTT > 0):
            RTT=0.875*RTT + 0.125*tcp.RTT
    print("Average RTT:",RTT,end='\n')
    print("Theoretical throughput:",(((3/2)**(1/2))*flow.tcpArray[2].MSS)/(RTT*(rate**(1/2))),end='\n')
#Print the first 10 congestion window sizes
def congestionWindow(flow):
    i=0
    for con in flow.frist10CongestionWin:
        i+=1
        print(i,"Congestion window sizes:", con) 
        
resolvePcap()
i=0
for flow in tcpFlows:
    if(flow.destinationPort == 80):
        i=i+1
        print("Flow:",i,"| Source Port:",flow.sourcePort,"| Destination Port:",flow.destinationPort,end="\n")
        congestionWindow(flow)
        print(end="\n")
        
for flow in tcpFlows:
    if(flow.destinationPort == 80):
        print("Source Port:",flow.sourcePort,"-> Destination Port:",flow.destinationPort)
        print("Number of retransmission: Due to triple duplicate ack:{",flow.tripleDuplicateAck, "}. Due to timeout:{",flow.timeout,end=" }.\n\n")
for flow in tcpFlows:
    if(flow.sourcePort == 80):
        print("Source Port:",flow.sourcePort,"-> Destination Port:",flow.destinationPort)
        print("Number of retransmission: Due to triple duplicate ack:{",flow.tripleDuplicateAck, "}. Due to timeout:{",flow.timeout,end=" }.\n\n")