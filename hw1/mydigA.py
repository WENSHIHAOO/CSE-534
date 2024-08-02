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
def recursiveParse(server:dns.message.Message, message:dns.message.Message,)->dns.message.Message:
    try:
        #get parsed by recursion
        response = dns.query.udp(message, str(server), 3);
        #size is the size of the data obtained.
        global size;
        size=size+len(response.answer)+len(response.additional)+len(response.authority);
        #When there is no answer, additional or authority in the parsed content, it means that the server has not responded and returns to the previous layer.
        if(len(response.answer)==0):
            if(len(response.additional)==0):
                if(len(response.authority)==0):
                    return None;
                #There is no answer and additional, but when there is authority, it means that the server has responded.
                else:
                    return response;
            #If there is no answer, if there is an additional, use the additional server for recursive analysis.
            else:
                for additional in response.additional:
                    if(additional.rdtype==1):
                        response = recursiveParse(additional[0], message);
                        if(response != None):
                            return response;
        #When there is an answer, the answer is returned first.
        else:
            return response;
    except Exception as e:
        response = None
    return response;
        
def main(domain:str, queryType:str)->dns.message.Message:
    message= dns.message.make_query(domain, queryType);
    response = None;
    #When the root server does not respond, contact the next root server.
    i=0;
    while((i<len(rootServer)) & (response==None)):
        try:
            response = dns.query.udp(message, rootServer[i], 3);
            #size is the size of the data obtained.
            global size;
            size=size+len(response.answer)+len(response.additional)+len(response.authority);
            #When there is no additional, it means that there is no TLD server, which means that the root server does not respond.
            if(len(response.additional)==0):
                response = None;
            else:
                for additional in response.additional:
                    #Contact the TLD server for the next recursive parsing
                    response = recursiveParse(additional[0], message);
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
end=time.time();
#print format
print("\nQUESTION SECTION:")
print(domain, "IN", queryType, "\n");
print("ANSWER SECTION:");
if(res==None):
    res=response;
if(len(res.answer)==0):
    for authority in res.authority:
        print(domain, "IN", queryType, authority[0]);
else:
    for answer in res.answer:
        print(domain, "IN", queryType, answer[0]);
print("\nQuery time: %.3f sec"%(end-start));
print("WHEN:", datetime.now().strftime('%b %d %H:%M:%S %Y'));
print("MSG SIZE rcvd: %s"%(size));