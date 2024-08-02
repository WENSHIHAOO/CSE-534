import sys
import dns.resolver
import time
from datetime import datetime
#13 root servers.
rootServer = ["198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33"];

size=0;
verify=False;
def KSKverifyZSK(nextServer, nextServerName, server):
    global verify;
    try:
        DsZSK = dns.message.make_query(nextServerName, dns.rdatatype.DS, want_dnssec=True)
        responseDsZSK = dns.query.udp(DsZSK, server, 3)
        DnskeyKSK = dns.message.make_query(nextServerName, dns.rdatatype.DNSKEY, want_dnssec=True)
        responseDnskeyKSK = dns.query.udp(DnskeyKSK, nextServer, 3)
        # verify if the KSK given when contacting nextServer.
        if(len(responseDnskeyKSK.answer[0].items)==0):
            print("DNSSEC not supported.")
            return False;
        KSK=None;
        for it in responseDnskeyKSK.answer[0].items:
            if(it.flags==257):
                KSK=it;
                break;
        if(KSK==None):
            print("KSK not found.")
            return False;
        # verify if the DS given when contacting server.
        if(len(responseDsZSK.answer[0].items)==0):
            print("DS not supported.")
            return False
        #Make hash
        makeDs = dns.dnssec.make_ds(nextServerName, KSK, 'SHA256');
        #compare hash
        for it in responseDsZSK.answer[0].items:
            if(makeDs==it):
                verify=True;
                break;
            else:
                print("Not verify")
                return False
        return True
    except Exception as e:
        if(verify):
            return True
        return False
    
    
def recursiveParse(server:str, domain:str, queryType:str, SP:int)->dns.message.Message:
    try:
        messageDnssec= dns.message.make_query(str(domain), queryType, want_dnssec=True);
        name=str(dns.name.from_text(domain).split(SP)[1]);
        messageDnssecZSK=dns.message.make_query(name, dns.rdatatype.DNSKEY, want_dnssec=True);
        #Verify DNSSEC: ZSK verify RRSET
        responseDnssec = dns.query.udp(messageDnssec, server, 3);
        responseDnssecZSK = dns.query.udp(messageDnssecZSK, server, 3);
        #size is the size of the data obtained.
        global size;
        size=size+len(responseDnssec.answer)+len(responseDnssec.additional)+len(responseDnssec.authority)
        +len(responseDnssecZSK.answer)+len(responseDnssecZSK.additional)+len(responseDnssecZSK.authority);
        if(len(responseDnssec.answer)>0 and len(responseDnssecZSK.answer)>0):
            try:
                #response.answer[0] is rrset, response.answer[1] is rrsig.
                dns.dnssec.validate(responseDnssec.answer[0], responseDnssec.answer[1], {dns.name.from_text(name):responseDnssecZSK.answer[0]})
            except Exception as e:
                print("DNSSec verification failed.");
                return None;
        elif(len(responseDnssec.authority)>0 and len(responseDnssecZSK.answer)>0):
            try:
                #response.authority[1] is rrset, response.authority[2] is rrsig.
                dns.dnssec.validate(responseDnssec.authority[1], responseDnssec.authority[2], {dns.name.from_text(name):responseDnssecZSK.answer[0]})
            except Exception as e:
                print("DNSSec verification failed.");
                return None;
        elif(SP<3):
            print("DNSSEC not supported.");
            return None;
        #NOT DNSSEC
        #get parsed by recursion
        message= dns.message.make_query(domain, queryType);
        response = dns.query.udp(message, str(server), 3);
        #size is the size of the data obtained.
        size=size+len(response.answer)+len(response.additional)+len(response.authority);
        #When there is no answer, additional or authority in the parsed content, it means that the server has not responded and returns to the previous layer.
        if(len(response.answer)==0):
            if(len(response.additional)==0):
                if(len(response.authority)==0):
                    return None;
                #There is no answer and additional, but when there is authority, it means that the server has responded.
                else:
                    return response;
            ##If there is no answer, if there is an additional, use the additional server for recursive analysis.
            else:
                for additional in response.additional:
                    #KSK verifies ZSK
                    if additional.rdtype==1:
                        verify = KSKverifyZSK(str(additional[0]), str(response.authority[0].name), str(server))
                        if not verify:
                            return None;
                    if(additional.rdtype==1):
                        response = recursiveParse(str(additional[0]), str(domain), queryType, SP+1);
                        if(response != None):
                            return response;
        #When there is an answer, the answer is returned first.
        else:
            return response;
    
    except Exception as e:
        response = None
    return response;
        
def main(domain:str, queryType:str)->dns.message.Message:
    messageDnssec= dns.message.make_query(domain, queryType, want_dnssec=True);
    rootName=str(dns.name.from_text(domain).split(1)[1]);
    messageDnssecZSK=dns.message.make_query(rootName, dns.rdatatype.DNSKEY, want_dnssec=True);
    response=None;
    #When the root server does not respond, contact the next root server.
    i=0;
    try:
        #Verify DNSSEC: ZSK verify RRSET
        responseDnssec = dns.query.udp(messageDnssec, rootServer[i], 3);
        responseDnssecZSK = dns.query.udp(messageDnssecZSK, rootServer[i], 3);
        #size is the size of the data obtained.
        global size;
        size=size+len(responseDnssec.answer)+len(responseDnssec.additional)+len(responseDnssec.authority)
        +len(responseDnssecZSK.answer)+len(responseDnssecZSK.additional)+len(responseDnssecZSK.authority);
        if(len(responseDnssec.answer)>0 and len(responseDnssecZSK.answer)>0):
            try:
                #response.answer[0] is rrset and response.answer[1] is rrsig.
                dns.dnssec.validate(responseDnssec.answer[0], responseDnssec.answer[1], {dns.name.from_text(rootName):responseDnssecZSK.answer[0]})
            except Exception as e:
                print("DNSSec verification failed.");
                return None;
        elif(len(responseDnssec.authority)>0 and len(responseDnssecZSK.answer)>0):
            try:
                #DNSKEY is zsk
                #'.' zsk
                #DS is rrset, which is domain
                #The signature RRSIG used by zsk to verify the DS
                #response.authority[1] is rrset and response.authority[2] is rrsig.
                dns.dnssec.validate(responseDnssec.authority[1], responseDnssec.authority[2], {dns.name.from_text(rootName):responseDnssecZSK.answer[0]})
            except Exception as e:
                print("DNSSec verification failed.");
                return None;
        else:
            print("DNSSEC not supported.");
            return None;
        #非DNSSEC
        message= dns.message.make_query(domain, queryType);
        response = dns.query.udp(message, rootServer[i], 3);
        #size is the size of the data obtained.
        size=size+len(response.answer)+len(response.additional)+len(response.authority);
        #When there is no additional, it means that there is no TLD server, which means that the root server does not respond.
        if(len(response.additional)==0):
            response = None;
        else:
            for additional in response.additional:
                #KSK verifies ZSK
                if additional.rdtype==1:
                    verify = KSKverifyZSK(str(additional[0]), str(response.authority[0].name), rootServer[i])
                    if not verify:
                        return None;
                #Contact the TLD server for the next recursive parsing
                response = recursiveParse(str(additional[0]), str(domain), queryType, 2);
                #When the response is not None, it means that the IP or CNAME has been obtained.
                if(response != None):
                    break;
    except Exception as e:
        response = None
    i+=1;
    return response;

#main: used to input domain and query type
if(len(sys.argv)<3):
    print("Missing domain or query type.");
    exit();
domain=sys.argv[1];
queryType=sys.argv[2];
start=time.time();
#CNAME: get the CNAME of the domain
response = main(domain, dns.rdatatype.CNAME)
if(response==None):
    print("You need a VPN");
    exit();
if(len(response.answer)==0):
    cName = (str)(response.authority[0][0]);
else:
    cName = (str)(response.answer[0][0]);
#IP: get the IP of the domain from the CNAME
res = main(cName, queryType);
if(res!=None):
    end=time.time();
    #print format
    print("DNSSEC is configured and everything is verified");
    print("\nQUESTION SECTION:")
    print(domain, "IN", queryType, "\n");
    print("ANSWER SECTION:");
    if(len(res.answer)==0):
        for authority in res.authority:
            print(domain, "IN", queryType, authority[0]);
    else:
        for answer in res.answer:
            print(domain, "IN", queryType, answer[0]);
    print("\nQuery time: %.3f sec"%(end-start));
    print("WHEN:", datetime.now().strftime('%b %d %H:%M:%S %Y'));
    print("MSG SIZE rcvd: %s"%(size));
