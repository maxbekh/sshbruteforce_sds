from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from datetime import datetime, timedelta
import logging

class SSHFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        print("SSHFirewall::__init__")
        super(SSHFirewall, self).__init__(*args, **kwargs)
        self.ssh_attempts = {}
        self.blocked_ips = set()
        self.logger.propagate = False  # Disable propagation to root logger
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        self.logger.addHandler(stream_handler)

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        print("SSHFirewall::packet_in_handler")
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip.proto == inet.IPPROTO_TCP:
                tcp = pkt.get_protocol(tcp.tcp)
                if tcp.dst_port == 22:  # SSH port
                    src_ip = ip.src
                    self.logger.debug(f"Received SSH packet from {src_ip}")
                    now = datetime.now()

                    if src_ip not in self.ssh_attempts:
                        self.ssh_attempts[src_ip] = []

                    self.ssh_attempts[src_ip] = [attempt for attempt in self.ssh_attempts[src_ip] if attempt > now - timedelta(minutes=10)]
                    self.ssh_attempts[src_ip].append(now)

                    if len(self.ssh_attempts[src_ip]) > 10 and src_ip not in self.blocked_ips:
                        self.install_block_rule(dp, parser, ofp, src_ip)
                        self.blocked_ips.add(src_ip)
                        self.logger.info(f"Blocked SSH brute-force attempt from {src_ip}")

    def install_block_rule(self, dp, parser, ofp, src_ip):
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip)
        actions = []
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, match=match, instructions=inst)
        dp.send_msg(mod)
        self.logger.debug(f"Installed block rule for {src_ip}")