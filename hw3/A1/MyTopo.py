from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel
from mininet.cli import CLI

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."
    # pylint: disable=arguments-differ
    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )
    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()
        
class MyTopo(Topo):

    def build(self):   
        H1=self.addHost('H1', ip='170.0.0.1/16')
        R1=self.addNode('R1', cls=LinuxRouter, ip='170.0.0.2/16')
        R2=self.addNode('R2', cls=LinuxRouter, ip='173.0.0.1/16')
        R3=self.addNode('R3', cls=LinuxRouter, ip='174.0.0.1/16')
        R4=self.addNode('R4', cls=LinuxRouter, ip='175.0.0.2/16')
        H2=self.addHost('H2', ip='175.0.0.1/16')
        
        self.addLink(H1,R1)
        self.addLink(R4,H2)
        self.addLink(R2,R4)
        self.addLink(R3,R4)
        self.addLink(R1,R2)
        self.addLink(R1,R3)
    
def run():
    topo = MyTopo()
    net = Mininet(topo=topo)
    net.start()
    
    net.get("R1").cmd("ifconfig R1-eth1 171.0.0.1") 
    net.get("R1").cmd("ifconfig R1-eth2 172.0.0.1")
    net.get("R2").cmd("ifconfig R2-eth1 171.0.0.2") 
    net.get("R3").cmd("ifconfig R3-eth1 172.0.0.2")
    net.get("R4").cmd("ifconfig R4-eth1 173.0.0.2")
    net.get("R4").cmd("ifconfig R4-eth2 174.0.0.2")
    
    net.get("H1").cmd("route add default gw 170.0.0.2")
    net.get("H2").cmd("route add default gw 175.0.0.2")
    
    net.get("R1").cmd("ip route add 173.0.0.0/16 via 171.0.0.2")
    net.get("R1").cmd("ip route add 174.0.0.0/16 via 172.0.0.2")
    net.get("R1").cmd("ip route add 175.0.0.0/16 via 172.0.0.2")
    
    net.get("R2").cmd("ip route add 170.0.0.0/16 via 171.0.0.1")
    net.get("R2").cmd("ip route add 172.0.0.0/16 via 171.0.0.1")
    net.get("R2").cmd("ip route add 174.0.0.0/16 via 173.0.0.2")
    net.get("R2").cmd("ip route add 175.0.0.0/16 via 173.0.0.2")
    
    net.get("R3").cmd("ip route add 170.0.0.0/16 via 172.0.0.1")
    net.get("R3").cmd("ip route add 171.0.0.0/16 via 172.0.0.1")
    net.get("R3").cmd("ip route add 173.0.0.0/16 via 174.0.0.2")
    net.get("R3").cmd("ip route add 175.0.0.0/16 via 174.0.0.2")

    net.get("R4").cmd("ip route add 170.0.0.0/16 via 173.0.0.1")
    net.get("R4").cmd("ip route add 171.0.0.0/16 via 173.0.0.1")
    net.get("R4").cmd("ip route add 172.0.0.0/16 via 174.0.0.1")
    
    CLI(net)
    net.stop()
      
if __name__ == '__main__':
    setLogLevel( 'info' )
    run()