import dpkt
tcpFlows=[]
tcpFlows1081=[]
tcpFlows1082=[]
https=[]
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
        self.tcpArray=[]
        self.http=0
        self.totalBufLen=0

class HTTP:
    def __init__(self):
        self.packetType=0
        self.tuple=0
        
def resolvePcap():
    global tcpFlows
    global https
    f= open("http_1080.pcap", 'rb')
    pcap = dpkt.pcap.Reader(f)
    num=0
    for ts, buf in pcap:
        num+=1
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
        if(buf[47]%2 == 1):
            tcp.flagFin=1
            if(num<50):
                flow.http='1.0'
        if((buf[47]>>4)%2 == 1):tcp.flagAck=1
        if((buf[47]>>1)%2 == 1):tcp.flagSyn=1
        if(tcp.flagSyn==1):tcp.windowSize=(buf[48] * 256) + buf[49]; tcp.MSS=(buf[56] * 256) + buf[57]
        else: tcp.windowSize=((buf[48] * 256) + buf[49])*16384; tcp.MSS=flow.tcpArray[0].MSS
        #tcp.MSS=(buf[56] * 256) + buf[57]
        tcp.timestmp=ts
        tcp.bufLen=len(buf)
        flow.totalBufLen+=len(buf)
        flow.totalTcp=flow.totalTcp+1
        for f in reversed(flow.tcpArray):
            if(ts-f.timestmp>0.002): break 
            if(f.seqNum==tcp.seqNum and tcp.ackNum==f.ackNum):
                haveFlowTcp=False
                break
        if(haveFlowTcp): flow.tcpArray.append(tcp); flow.usefulTcp=flow.usefulTcp+1
        if(haveFlow): tcpFlows.append(flow)
        if(haveFlowTcp and (tcp.sourcePort == 80)):
            for t in tcpFlows:
                if(t.sourcePort==tcp.destinationPort):
                    for f in reversed(t.tcpArray):
                        if(f.ackNum==tcp.seqNum and tcp.ackNum==f.seqNum):
                            f.RTT=ts-f.timestmp
                            break
                    break
        if len(buf) > 69:
            http=HTTP()
            st = chr(buf[66]) + chr(buf[67]) + chr(buf[68]) + chr(buf[69]) 
            if(st=='HTTP'):
                http.packetType='Response'
                http.tuple=(tcp.sourcePort, tcp.destinationPort, tcp.seqNum, tcp.ackNum)
                https.append(http)
            elif(st.strip()=='GET' or st.strip()=='POST'):
                http.packetType='Request '
                http.tuple=(tcp.sourcePort, tcp.destinationPort, tcp.seqNum, tcp.ackNum)
                https.append(http)
                
def reassemble():
    print("Packet type | < source, dest, seq, ack>", end="\n")
    for http in https:
        print(http.packetType,"| <", http.tuple[0],",", http.tuple[1],",", http.tuple[2],",", http.tuple[3], end=">\n")
                
def resolvePcap1081And1082(tcpFlows, pcap):
    num=0
    for ts, buf in pcap:
        num+=1
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
        if(buf[47]%2 == 1):
            tcp.flagFin=1
            if(num<50):
                flow.http='1.0'
        if((buf[47]>>4)%2 == 1):tcp.flagAck=1
        if((buf[47]>>1)%2 == 1):tcp.flagSyn=1
        if(tcp.flagSyn==1):tcp.windowSize=(buf[48] * 256) + buf[49]; tcp.MSS=(buf[56] * 256) + buf[57]
        else: tcp.windowSize=((buf[48] * 256) + buf[49])*16384; tcp.MSS=flow.tcpArray[0].MSS
        #tcp.MSS=(buf[56] * 256) + buf[57]
        tcp.timestmp=ts
        tcp.bufLen=len(buf)
        flow.totalBufLen+=len(buf)
        flow.totalTcp=flow.totalTcp+1
        for f in reversed(flow.tcpArray):
            if(ts-f.timestmp>0.002): break 
            if(f.seqNum==tcp.seqNum and tcp.ackNum==f.ackNum):
                haveFlowTcp=False
                break
        if(haveFlowTcp): flow.tcpArray.append(tcp); flow.usefulTcp=flow.usefulTcp+1
        if(haveFlow): tcpFlows.append(flow)
        if(haveFlowTcp and (tcp.sourcePort == 80)):
            for t in tcpFlows:
                if(t.sourcePort==tcp.destinationPort):
                    for f in reversed(t.tcpArray):
                        if(f.ackNum==tcp.seqNum and tcp.ackNum==f.seqNum):
                            f.RTT=ts-f.timestmp
                            break
                    break
                
def protocolOfHTTP(flows, name):
    for flow in flows:
        if(flow.http=='1.0'):
            flows[0].http='1.0'
    haveFin=0
    if(flows[0].http==0):
        for flow in flows:
            for tcp in flow.tcpArray:
                if(tcp.flagFin==1):
                    haveFin+=1
        if((haveFin/2)>2):
            flows[0].http='1.1'
        else:
            flows[0].http='2.0'
    print("HTTP protocol of the PCAP file:",name,"= HTTP",flows[0].http)
    
def compareLoadTime(flows):
    earliest=flows[0].tcpArray[0].timestmp
    latest=0
    for flow in flows:
        for tcp in flow.tcpArray:
            if(tcp.timestmp<earliest):
                earliest=tcp.timestmp
            break
    for flow in flows:
        for tcp in reversed(flow.tcpArray):
            if(tcp.timestmp>latest):
                latest=tcp.timestmp
            break
    print("The site load time:","HTTP",flows[0].http,"=",latest-earliest,"Seconds")

def comparePacketsAndRawBytes(flows):
    packets=0
    RawBytes=0
    for flow in flows:
        packets+=flow.totalTcp
        RawBytes+=flow.totalBufLen
    print("HTTP",flows[0].http)
    print("Number of packets:",packets)
    print("Number of raw bytes:",RawBytes,"Bytes")
        
resolvePcap()
reassemble()

print(end="\n")
protocolOfHTTP(tcpFlows, "http_1080.pcap")
f1= open("tcp_1081.pcap", 'rb')
pcap1 = dpkt.pcap.Reader(f1)
resolvePcap1081And1082(tcpFlows1081, pcap1)
protocolOfHTTP(tcpFlows1081, "tcp_1081.pcap")
f2= open("tcp_1082.pcap", 'rb')
pcap2 = dpkt.pcap.Reader(f2)
resolvePcap1081And1082(tcpFlows1082, pcap2)
protocolOfHTTP(tcpFlows1082, "tcp_1082.pcap")

print(end="\n")
compareLoadTime(tcpFlows)
compareLoadTime(tcpFlows1081)
compareLoadTime(tcpFlows1082)

print(end="\n")
comparePacketsAndRawBytes(tcpFlows)
comparePacketsAndRawBytes(tcpFlows1081)
comparePacketsAndRawBytes(tcpFlows1082)