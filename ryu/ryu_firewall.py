from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.ofproto import ofproto_v1_3
import time

class SSHConnectionMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SSHConnectionMonitor, self).__init__(*args, **kwargs)
        self.ssh_connections = {}
        self.blocked_ips = set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip4 = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip4 and tcp_pkt and tcp_pkt.dst_port == 22:
            src_ip = ip4.src
            self.log_ssh_attempt(src_ip)
            if self.check_ssh_threshold(src_ip):
                self.block_ip(datapath, parser, ofproto, src_ip)
            else:
                # Install a high-priority flow rule to forward packets from non-blocked IPs
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
                datapath.send_msg(mod)
        else:
            # Install a low-priority flow rule to forward non-SSH packets from non-blocked IPs
            if ip4 and ip4.src not in self.blocked_ips:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip4.src)
                actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
                datapath.send_msg(mod)

        # Optionally, you can also forward the packet out to avoid packet loss
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def log_ssh_attempt(self, src_ip):
        self.logger.info(f"SSH connection attempt from {src_ip}")
        if src_ip not in self.ssh_connections:
            self.ssh_connections[src_ip] = [time.time()]
        else:
            self.ssh_connections[src_ip].append(time.time())

    def check_ssh_threshold(self, src_ip):
        if src_ip not in self.blocked_ips:
            now = time.time()
            ten_minutes_ago = now - 600
            connection_times = self.ssh_connections.get(src_ip, [])
            recent_connections = [t for t in connection_times if t > ten_minutes_ago]
            if len(recent_connections) > 10:
                return True
        return False

    def block_ip(self, datapath, parser, ofproto, src_ip):
        self.logger.info(f"Blocking IP address {src_ip} due to excessive SSH connection attempts")
        self.blocked_ips.add(src_ip)