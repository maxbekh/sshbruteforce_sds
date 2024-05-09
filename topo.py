import sys
sys.path.append('../mininet')

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.util import waitListening
from time import sleep

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def build(self, n=2):
        switch = self.addSwitch('switch1')
    
        server1 = self.addHost('server1',ip="10.0.0.2/24")
        self.addLink(server1, switch)
        
        client1 = self.addHost('client1',ip="10.0.0.3/24")
        self.addLink(client1, switch)
        
        attacker1 = self.addHost('attacker1',ip="10.0.0.4/24")
        self.addLink(attacker1, switch)
        


def init_users(hosts):
    print("*** Creating users on hosts\n")
    for host in hosts:
        if host.name == 'server1':
            host.cmd(f'echo "bob:test" | sudo chpasswd')
            # add user to sudoers with usermod -aG sudo <username>
            host.cmd('sudo usermod -aG sudo bob')
        if host.name == 'client1':
            host.cmd(f'echo "bob:test" | sudo chpasswd')
            host.cmd('sudo usermod -aG sudo bob')
        if host.name == 'attacker1':
            host.cmd(f'echo "attacker:test" | sudo chpasswd')
            host.cmd('sudo usermod -aG sudo attacker')
        
            
    
    
    
def start_sshd(hosts):
    print("*** Starting sshd on hosts:\n")
    for host in hosts:
        host.cmd( '/usr/sbin/sshd -D &')
    print( "\n*** Waiting for ssh daemons to start")
    sleep(5)
    print( "\n*** Hosts are running sshd at the following addresses:\n" )
    for host in hosts:
        print( host.name, host.IP(), '\n' )
        
        
def simpleTest():
    "Create and test a simple network"
    topo = SingleSwitchTopo(n=4)
    net = Mininet(topo)
    net.start()
    print( "Dumping host connections" )
    dumpNodeConnections(net.hosts)
    print( "Testing network connectivity" )
    net.pingAll()
    print( "Testing sshd service" )
    start_sshd(net.hosts)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
