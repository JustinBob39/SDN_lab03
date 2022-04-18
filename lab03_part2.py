from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from ryu.lib import hub
from operator import attrgetter
import networkx as nx

GET_WORKLOAD_INTERVAL = 4
topo_events = [event.EventSwitchEnter, event.EventLinkAdd, event.EventPortAdd]


class Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Switch, self).__init__(*args, **kwargs)

        # global data structure to save the mac_to_port[dpid][eth_src] = port
        # layer 2 learning
        self.mac_to_port = {}

        # global data structure to save the arp_in_port[dpid][arp_src_mac][arp_dst_ip] = port
        # avoid ARP loop storm
        self.arp_in_port = {}

        # global data structure to save the ss_link[(dpid, next_dpid)] = (port, next_port)
        # compare bandwidth load convenience max
        self.ss_link = {}

        # global data structure to save the switch_port[dpid] = {port1, port2, ...}
        # port connect switch
        self.switch_port = {}

        # global data structure to save the hs_link[ip] = (dpid, port_no)
        # port connect host
        self.hs_link = {}

        # global data structure to save the datapath[dpid] = datapath
        # hand out flow table entry on the path of ipv4
        self.datapath = {}

        # global data structure to save the port_stat[dpid][port_no] = (tx_bytes, rx_bytes,duration_sec, duration_nsec)
        # calculate the workload of the switch port
        self.port_stat = {}

        # global data structure to save the workload[dpid][port_no] = speed / load
        self.workload = {}

        # use this api to get the topo of switches
        self.topology_api_app = self

        # global data structure to save the topo map
        self.topo_map = nx.Graph()

        # thread to get_workload
        self.get_workload_thread = hub.spawn(self.get_workload)

    # add a flow table entry in switch
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        dp = datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # construct a FlowMod message
        # send to a switch to add a flow table entry
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    # set the table_miss entry
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id

        # use the msg.data to make a packet
        # extract the content of the packet of different protocols
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # learn a mac and port relation avoid FLOOD
        in_port = msg.match['in_port']
        eth_src = eth_pkt.src
        if eth_src not in self.mac_to_port[dpid].keys():
            self.mac_to_port[dpid][eth_src] = in_port

        # if is arp call function to handle
        if isinstance(arp_pkt, arp.arp):
            # print('handle an arp packet {}'.format(arp_pkt))
            self.handle_arp(arp_pkt, msg)

        # if is ipv4 call function to handle
        if isinstance(ipv4_pkt, ipv4.ipv4):
            # print('handle an ipv4 packet {}'.format(ipv4_pkt))
            self.handle_ipv4(ipv4_pkt, msg)

    def handle_arp(self, arp_pkt, msg):

        # define the out port and eth_dst for later convenience
        out_port = None
        eth_dst = None

        # get the dpid ofp parser in_port
        dpid = msg.datapath.id
        ofp = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        in_port = msg.match['in_port']

        # learn a switch-host relation
        # if this port connect a host
        # deal with the silent host phenomenon
        if in_port not in self.switch_port[dpid]:
            self.hs_link[arp_pkt.src_ip] = (dpid, in_port)

        # this is an arp request
        if arp_pkt.opcode == arp.ARP_REQUEST:

            # get the arp_dst_ip and arp_src_mac
            arp_dst_ip = arp_pkt.dst_ip
            arp_src_mac = arp_pkt.src_mac

            # if not exist the record then record
            # if exist the record then compare whether the same
            if arp_src_mac not in self.arp_in_port[dpid].keys():
                self.arp_in_port[dpid].setdefault(arp_src_mac, {})
                self.arp_in_port[dpid][arp_src_mac][arp_dst_ip] = in_port
            else:
                if arp_dst_ip not in self.arp_in_port[dpid][arp_src_mac].keys():
                    self.arp_in_port[dpid][arp_src_mac][arp_dst_ip] = in_port
                else:
                    if in_port != self.arp_in_port[dpid][arp_src_mac][arp_dst_ip]:
                        print('Drop an arp request to avoid loop storm.')
                        return

            # ARP request default to FLOOD
            out_port = ofp.OFPP_FLOOD

        # this is an arp response
        else:

            # get the eth_dst
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            eth_dst = eth_pkt.dst

            # decide the out_port
            if eth_dst in self.mac_to_port[dpid].keys():
                out_port = self.mac_to_port[dpid][eth_dst]
            else:
                out_port = ofp.OFPP_FLOOD

        # deal with the packet going to send
        actions = [parser.OFPActionOutput(out_port)]

        # add a flow table entry to the switch
        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=ofp.OFPP_ANY, eth_dst=eth_dst)
            self.add_flow(msg.datapath, 10, match, actions, 90, 180)

        # send packet out deal with the packet
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        msg.datapath.send_msg(out)

    def handle_ipv4(self, ipv4_pkt, msg):

        # get the ofp and the parser
        ofp = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser

        # get the src and dst ip address
        ipv4_src = ipv4_pkt.src
        ipv4_dst = ipv4_pkt.dst

        # get the start switch and start port
        dpid_begin = self.hs_link[ipv4_src][0]
        port_begin = self.hs_link[ipv4_src][1]

        # get the final switch and final port
        dpid_final = self.hs_link[ipv4_dst][0]
        port_final = self.hs_link[ipv4_dst][1]

        # find the shortest path
        short_path = self.find_path(dpid_begin, dpid_final)
        print('Path from {} to {} is {}'.format(ipv4_src, ipv4_dst, short_path))

        # add flow entry to the switches on the path
        for i in range(0, len(short_path)):

            # current switch to add table flow entry
            cur_switch = short_path[i]

            # add flow table entry to the first switch
            if i == 0:

                # from ipv4_src to ipv4_dst
                next_switch = short_path[i + 1]
                out_port = self.ss_link[(cur_switch, next_switch)][0]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

                # from ipv4_dst to ipv4_src
                out_port = port_begin
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

            # add flow table entry to the final switch
            elif i == len(short_path) - 1:

                # from ipv4_src to ipv4_dst
                out_port = port_final
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

                # from ipv4_dst to ipv4_src
                pre_switch = short_path[i - 1]
                out_port = self.ss_link[(cur_switch, pre_switch)][0]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

            # add flow table entry to the middle switch
            else:

                pre_switch = short_path[i - 1]
                next_switch = short_path[i + 1]

                port1 = self.ss_link[(cur_switch, next_switch)][0]
                port2 = self.ss_link[(cur_switch, pre_switch)][0]

                # from ipv4_src to ipv4_dst
                out_port = port1
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

                # from ipv4_dst to ipv4_src
                out_port = port2
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

        # send the packet to the switch
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:

            # send packet out to the final switch
            data = msg.data
            out_port = port_final
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=self.datapath[dpid_final], buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=ofp.OFPP_CONTROLLER, actions=actions, data=data)
            self.datapath[dpid_final].send_msg(out)
            print('First ipv4 packet directly send to switch {}, it forward the packet to port {}'
                  .format(dpid_final, port_final))

        else:

            # send packet out to the first switch
            out_port = port_begin
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.buffer_id,
                                      in_port=msg.match['in_port'], actions=actions, data=data)
            msg.datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no

            # ignore the local port
            if port_no == ofproto_v1_3.OFPP_LOCAL:
                # print('This is a LOCAL PORT.')
                continue

            # the port has initial record
            if port_no in self.port_stat[dpid].keys():

                # calculate the workload / speed
                last_bytes = self.port_stat[dpid][port_no][0] + self.port_stat[dpid][port_no][1]
                cur_bytes = stat.tx_bytes + stat.rx_bytes

                last_second = self.port_stat[dpid][port_no][3] * 10 ** (-9) + self.port_stat[dpid][port_no][2]
                cur_second = stat.duration_nsec * 10 ** (-9) + stat.duration_sec

                bps = (cur_bytes - last_bytes) * 8 / (cur_second - last_second)
                mbps = bps / 10 ** 6

                # record the workload
                self.workload[dpid][port_no] = mbps

                # update the port_stat record
                self.port_stat[dpid][port_no] = (
                    stat.tx_bytes, stat.rx_bytes, stat.duration_sec, stat.duration_nsec)

            # the port does not have initial record
            else:

                # record port_stat
                self.port_stat[dpid][port_no] = (
                    stat.tx_bytes, stat.rx_bytes, stat.duration_sec, stat.duration_nsec)

    @set_ev_cls(topo_events)
    def get_topology(self, ev):

        # get all the switch
        switch_list = get_switch(self)
        for switch in switch_list:
            # record the datapath for later add flow table entry
            self.datapath[switch.dp.id] = switch.dp

            # make the value dictionary
            self.mac_to_port.setdefault(switch.dp.id, {})
            self.arp_in_port.setdefault(switch.dp.id, {})
            self.switch_port.setdefault(switch.dp.id, set())
            self.port_stat.setdefault(switch.dp.id, {})
            self.workload.setdefault(switch.dp.id, {})

        # get all the link
        link_list = get_link(self)
        for link in link_list:
            self.topo_map.add_edge(link.src.dpid, link.dst.dpid)
            self.ss_link[(link.src.dpid, link.dst.dpid)] = (link.src.port_no, link.dst.port_no)
            self.switch_port[link.src.dpid].add(link.src.port_no)
            self.switch_port[link.dst.dpid].add(link.dst.port_no)

        # print the edges of the topology
        print('Nodes of topo map:')
        print(self.topo_map.nodes)
        print('Edges of topo map:')
        print(self.topo_map.edges)

    def get_workload(self):
        while True:

            # send port_stats_request to every switch
            for dp in self.datapath.values():
                ofp = dp.ofproto
                parser = dp.ofproto_parser
                req = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
                dp.send_msg(req)

            # print the workload for every switch every port
            # print(self.workload)
            for dpid in self.workload.keys():
                for port_no in self.workload[dpid].keys():
                    if self.workload[dpid][port_no] > 1:
                        print('WorkLoad of Switch {} Port {} is {:.2f} Mbps'
                              .format(dpid, port_no, self.workload[dpid][port_no]))

            # sleep 4 seconds
            hub.sleep(GET_WORKLOAD_INTERVAL)

    def find_path(self, dpid_begin, dpid_final):
        all_path = list(nx.shortest_simple_paths(self.topo_map, dpid_begin, dpid_final))
        print(all_path)
        path_neck = []

        for i in range(0, len(all_path)):
            neck = []
            for j in range(0, len(all_path[i]) - 1):
                cur_switch = all_path[i][j]
                next_switch = all_path[i][j + 1]

                port1 = self.ss_link[(cur_switch, next_switch)][0]
                port2 = self.ss_link[(cur_switch, next_switch)][1]

                # print('workload of switch {} port {} is {} Mbps'
                #       .format(cur_switch, port1, self.workload[cur_switch][port1]))
                # print('workload of switch {} port {} is {} Mbps'
                #       .format(next_switch, port2, self.workload[next_switch][port2]))

                temp = 1000 - max(self.workload[cur_switch][port1], self.workload[next_switch][port2])
                neck.append(temp)
                # print('free bandwidth between switch{}:port{} -- switch{}:port{} is {} Mbps'
                #        .format(cur_switch, port1, next_switch, port2, temp))
            path_neck.append(min(neck))

        print(path_neck)
        index = path_neck.index(max(path_neck))
        return all_path[index]

