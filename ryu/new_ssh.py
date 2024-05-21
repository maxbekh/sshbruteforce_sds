from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ethernet, ipv4, tcp, packet
import time

BLOCK_IDLE_TIMEOUT = 600  # 10 minutes in seconds
ATTEMPT_THRESHOLD = 10

class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.attempt_counter = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if ip_pkt and tcp_pkt and tcp_pkt.dst_port == 22:
            # Get the TCP payload
            tcp_payload = tcp_pkt.payload

            # Check if the payload contains the SSH version string
            if b'SSH-2.0-' in tcp_payload:
                src_ip = ip_pkt.src
                current_time = time.time()

                if src_ip not in self.attempt_counter:
                    self.attempt_counter[src_ip] = []

                # Remove outdated attempts
                self.attempt_counter[src_ip] = [timestamp for timestamp in self.attempt_counter[src_ip] if current_time - timestamp < BLOCK_IDLE_TIMEOUT]

                # Record current attempt
                self.attempt_counter[src_ip].append(current_time)
                print(f"SSH attempt from {src_ip}. Current attempts: {len(self.attempt_counter[src_ip])}")

                if len(self.attempt_counter[src_ip]) > ATTEMPT_THRESHOLD:
                    self.block_ip(datapath, parser, src_ip, in_port)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)

    def block_ip(self, datapath, parser, ip, in_port):
        match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ip, ip_proto=6, tcp_dst=22)
        actions = []  # Drop packet by not specifying any action
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_CLEAR_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst,
            idle_timeout=BLOCK_IDLE_TIMEOUT,
            table_id=0,
        )
        datapath.send_msg(mod)
        self.logger.info(f"Blocking IP {ip} for SSH attempts.")
