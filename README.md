# SDN    lab03

这次实验，感觉比第二次要简单不少

对之前的代码进行了重构，优化了一些数据结构，效率更高，同时代码更容易看懂、结构更清晰



## Part 1

### 拓扑图

![image-20220418185158384](https://cdn.justinbob.site/typora/202204181852338.png)



### 端口负载测量原理

![image-20220418185945228](https://cdn.justinbob.site/typora/202204181859260.png)



向每个 `Switch` 都发送 `PortStatsRequest` 报文，请求所有端口的状态

```python
# send port_stats_request to every switch
for dp in self.datapath.values():
	ofp = dp.ofproto
	parser = dp.ofproto_parser
	req = parser.OFPPortStatsRequest(dp, 0, ofp.OFPP_ANY)
	dp.send_msg(req)
```



![image-20220418190001950](https://cdn.justinbob.site/typora/202204181900985.png)



用修饰器来接管 `EventOFPPortStatsReply` 事件

对比同一 `Switch` 两次相邻的 `Reply` 报文，端口总共收发的字节数之差是两次 `Reply` 报文之间端口传输的总数据量，计算出时间间隔，二者相除就是端口正在用于传输的带宽，即端口负载

$1 \space byte = 8 \space bits$

$1 \space Mbps = 10^6 \space bps$

```python
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

                last_second = self.port_stat[dpid][port_no][3] * 10**(-9) + self.port_stat[dpid][port_no][2]
                cur_second = stat.duration_nsec * 10**(-9) + stat.duration_sec

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
```



`OFPStats Arttribute`   

![image-20220418185753507](https://cdn.justinbob.site/typora/202204181857603.png)

我们主要利用 `port_no` 端口编号、`rx_bytes` 收到的字节数、`tx_bytes` 发送的字节数 几个属性

当然还有 `duration_sec`、`duration_nsec`，n 表示纳秒，$1s = 10^9 ns$，`nsec` 满了之后向 `sec` 进位



通过定义 `hub` 线程，实现周期性测量

`self.get_workload_thread = hub.spawn(self.get_workload)`



### 实验结果

启动拓扑文件 `sudo python3 topo_1972.py`

启动控制器 `ryu-manager lab03_part1.py --observe-links` ，记得加 `observe-links`

在 `mininet` 窗口中，`xterm MIT` 然后 `ipefr -s` 充当服务器，监听等待 `TCP` 连接

同样，在 `mininet` 窗口中，`xterm UCLA` 然后 `iperf -c 10.0.0.12 -b 50m -t 300` ，连接 `MIT` ，发送 `50 Mbps` 持续 300 s 的报文， `iperf` 需要一段时间才能稳定，刚开始的时候波动还是挺大的，后来就稳定了 `50 Mbps`

我采用的是最短跳数路径，实现起来很简单，找到路径后，双方顺着路径通信，可以看到路径上相关 `Switch` 的端口流量是正确的

![image-20220418192149477](https://cdn.justinbob.site/typora/202204181921602.png)



`iperf` 稳定后，带宽稳定在了 `50 Mbps`![image-20220418193006264](https://cdn.justinbob.site/typora/202204181930309.png)



这是 `UCLA` 的 `xterm` 窗口

![image-20220418192223361](https://cdn.justinbob.site/typora/202204181922400.png)

这是 `MIT` 的 `xterm` 窗口

![image-20220418192242315](https://cdn.justinbob.site/typora/202204181922360.png)



## Part 2

### 拓扑图

非常巧妙，很适合这部分实验

![image-20220418200113356](https://cdn.justinbob.site/typora/202204182001402.png)



### 路径查找原理

从源 `Host` 到目标 `Host` 之间有多条路径

每条路径上都有多条链路，可用带宽最小的链路称为瓶颈链路，限制着整条路径的传输能力

规定，`Switch` 和 `Switch` 之间的链路关联着两个交换机端口，取两个端口负载最大者为链路负载

本次实验中，`Switch` 之间的带宽都设置为 `1000 Mbps`，`Host` 和 `Switch` 之间的链路带宽无限大，因此瓶颈只会出现在 `Switch` 和 `Switch` 之间的链路

我们本次的任务，就是从所有路径中找出瓶颈链路带宽最大的那条路径



想法很简单，通过 `networkx` 的  `shortest_simple_paths` 找到所有的路径

然后计算出每条路径的瓶颈链路的带宽，就是哪条链路可用带宽最小， `append` 到 `path_neck` 列表里面

然后找到最大带宽的瓶颈链路对应的那个路径，返回即可

```python
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
            
            temp = 1000 - max(self.workload[cur_switch][port1], self.workload[next_switch][port2])
            neck.append(temp)
            
        path_neck.append(min(neck))

    print(path_neck)
    index = path_neck.index(max(path_neck))
    return all_path[index]
```



### 实验结果

在 `mininet` 中，开启 `SDC` 的 `xterm`，执行 `iperf -s` ；开启 McClellan 的 xterm，执行 `iperf -c 10.0.0.5 -t 300` ，制造链路负载压力

![image-20220418195232346](https://cdn.justinbob.site/typora/202204181952466.png)



此时所有的链路都处于空载状态，从 `McClellan` 到 `SDC` 找到了两条路径 `1 2 3 4 8 9` 和 `1 2 5 6 7 8 9`，选择好了后面这条

![image-20220418195029608](https://cdn.justinbob.site/typora/202204181950734.png)



然后执行 `SRI ping RAND`

找到了两条路径 `2 3 4 8 `  和 ` 2 5 6 7 8` ，前一条路径瓶颈带宽 `732 Mbps`，`SDC` 和 `McClellan` 之间的 `iperf` 占用了 `260 Mbps` 左右的链路带宽

选择了后面一条路，路径选择正确

<img src="https://cdn.justinbob.site/typora/202204182055322.jpg" alt="SDN3" style="zoom: 25%;" />

![image-20220418195449740](https://cdn.justinbob.site/typora/202204181954800.png)



两个 `xterm` 窗口

![image-20220418195904218](https://cdn.justinbob.site/typora/202204181959266.png)



## Addition

国防部对 `ARPANET` 网络流量的安全性非常看重，军方在 `TINKER` 设立了流量检查点用于分析经过的数
据，要求 `ILLINOIS` 到 `UTAH` 之间的所有流量都必须经过 `TINKER` 。

请你下发满足以下条件的路径：

* 满足路径点( `Waypoint-enforcement` )策略， `ILLINOIS` 到 `UTAH` 之间的所有流量都必须经过
    `TINKER` 
* 一端主机发出的数据包，在到达 `Waypoint` 之前不能途径另一端主机直连的交换机，例如
    `ILLINOIS UTAH USC TINKER USC UTAH` 
* 同时满足上述两个条件的路径中跳数最少的一条



### 实验思路

首先将路径分成两部分，第一部分是从 `ILLINOIS` 到 `TINKER`，第二部分是从 `TINKER` 到 `UTAH`

当然，也可以将上面 `ILLINOIS` 和 `UTAH` 位置进行交换，影响不大，代码实现很简单

因为最终跳数是最少的，又必须要经过 `TINKER` ，采用分治的思想，将路径一分为二，两个子路径必须也是最短的

将拓扑图拷贝一份，删掉 `UTAH` 直接相连接的 `Switch`，在这张图上找到 `ILLINOIS` 到 `TINKER` 的最短路径，必然不会经过 `UTAH` 直连的 `Switch`

然后再在拓扑图中，找到 `TINKER` 到 `UTAH` 的最短路径，两部分拼接起来就行

```python
new_topo = copy.deepcopy(self.topo_map)
new_topo.remove_node(dpid_final)
path = nx.shortest_path(new_topo, dpid_begin, TINKER)
path2 = nx.shortest_path(self.topo_map, TINKER, dpid_final)
print('Find path:')
print(path + path2[1::])
```



`TINKER` 那个 `Swtich` 收到流量后，要向正常路径转发，也要转发一份给连接的 `Host`，用组表实现

```python
buckets = []
dp = self.datapath[cur_switch]
actions = [parser.OFPActionOutput(1)]
buckets.append(parser.OFPBucket(actions=actions))
out_port = self.ss_link[(cur_switch, next_switch)][0]
actions = [parser.OFPActionOutput(out_port)]
buckets.append(parser.OFPBucket(actions=actions))
req = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_ADD, type_=ofp.OFPGT_ALL,
group_id=50, buckets=buckets)
dp.send_msg(req)
```



### 实验结果

`ILLINOIS` 的 `IP` 地址 `10.0.0.10`

![image-20220418201652793](https://cdn.justinbob.site/typora/202204182016872.png)



`UTAH` 的 `IP` 地址 `10.0.0.25`

![image-20220418201712859](https://cdn.justinbob.site/typora/202204182017914.png)



在 `Tinker` 中开启 `wireshark` 进行抓包

然后启动 `ILLINOIS ping UTAH` ，路径如下

![image-20220418202217026](https://cdn.justinbob.site/typora/202204182022082.png)

![image-20220418201732858](https://cdn.justinbob.site/typora/202204182017924.png)



可以看到， `UTAH` 和 `ILLINOIS` 之间的 `icmp` 报文全被 `Tinker` 捕获，监听成功

![image-20220418201904755](https://cdn.justinbob.site/typora/202204182019812.png)



`ping` 了 8 次，刚好 16 条 `icmp` 报文

![image-20220418201953366](https://cdn.justinbob.site/typora/202204182019427.png)



等等，可能有人发现了，为什么 `ping` 的时候 `icmp seq = 1` 的包被丢了，我也非常好奇

罪魁祸手就在这里，第一个交换机的输出端口写错了，我们需要做一点小小的修改

![image-20220424121643694](https://cdn.justinbob.site/typora/202204241216619.png)



修改部分如下，我也会同步到 `github` 上

![image-20220424121924783](https://cdn.justinbob.site/typora/202204241219858.png)



![image-20220424122036962](https://cdn.justinbob.site/typora/202204241220094.png)



![image-20220424122104583](https://cdn.justinbob.site/typora/202204241221686.png)



修改完的效果， `icmp seq = 1` 的包成功发了过去

![SDN_lab03_addition](https://cdn.justinbob.site/typora/202204241222061.png)



## Source Code

### Github Repository

https://github.com/JustinBob39/SDN_lab03.git

可以直接 `git clone` 下来



### Part 1

```python
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
        short_path = nx.shortest_path(self.topo_map, dpid_begin, dpid_final)
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

                last_second = self.port_stat[dpid][port_no][3] * 10**(-9) + self.port_stat[dpid][port_no][2]
                cur_second = stat.duration_nsec * 10**(-9) + stat.duration_sec

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
            for dpid in self.workload.keys():
                for port_no in self.workload[dpid].keys():
                    if self.workload[dpid][port_no] > 1:
                        print('WorkLoad of Switch {} Port {} is {:.2f} Mbps'
                              .format(dpid, port_no, self.workload[dpid][port_no]))

            # sleep 4 seconds
            hub.sleep(GET_WORKLOAD_INTERVAL)
```



### Part 2

```python
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
```



### Addition

```python
import copy

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
import networkx as nx

topo_events = [event.EventSwitchEnter, event.EventLinkAdd, event.EventPortAdd]
ILLINOIS = '10.0.0.10'
UTAH = '10.0.0.25'
TINKER = 9


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

        # use this api to get the topo of switches
        self.topology_api_app = self

        # global data structure to save the topo map
        self.topo_map = nx.Graph()

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

        # if ILLINOIS UTAH, go to army_handle
        if (ipv4_src == ILLINOIS and ipv4_dst == UTAH) or (ipv4_src == UTAH and ipv4_dst == ILLINOIS):
            self.army_handle(ipv4_src, ipv4_dst, dpid_begin, dpid_final,
                             port_begin, port_final, msg)
            return

        # find the shortest path
        short_path = nx.shortest_path(self.topo_map, dpid_begin, dpid_final)
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

    def army_handle(self, ipv4_src, ipv4_dst, dpid_begin, dpid_final, port_begin, port_final, msg):

        parser = self.datapath[1].ofproto_parser
        ofp = self.datapath[1].ofproto

        new_topo = copy.deepcopy(self.topo_map)
        new_topo.remove_node(dpid_final)
        path = nx.shortest_path(new_topo, dpid_begin, TINKER)
        path2 = nx.shortest_path(self.topo_map, TINKER, dpid_final)
        print('Find path:')
        print(path + path2[1::])

        for i in range(0, len(path)):

            # current switch to add table flow entry
            cur_switch = path[i]

            # add flow table entry to the first switch
            if i == 0:

                # from ipv4_src to ipv4_dst
                next_switch = path[i + 1]
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
            elif i == len(path) - 1:
                pre_switch = path[i - 1]
                next_switch = path2[1]

                # from ipv4_src to ipv4_dst
                buckets = []
                dp = self.datapath[cur_switch]
                actions = [parser.OFPActionOutput(1)]
                buckets.append(parser.OFPBucket(actions=actions))
                out_port = self.ss_link[(cur_switch, next_switch)][0]
                actions = [parser.OFPActionOutput(out_port)]
                buckets.append(parser.OFPBucket(actions=actions))
                req = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_ADD, type_=ofp.OFPGT_ALL,
                                         group_id=50, buckets=buckets)
                dp.send_msg(req)

                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                actions = [parser.OFPActionGroup(group_id=50)]
                self.add_flow(datapath=dp, priority=20, match=match, actions=actions,
                              idle_timeout=300, hard_timeout=600)

                # from ipv4_dst to ipv4_src
                buckets = []
                dp = self.datapath[cur_switch]
                actions = [parser.OFPActionOutput(1)]
                buckets.append(parser.OFPBucket(actions=actions))
                out_port = self.ss_link[(cur_switch, pre_switch)][0]
                actions = [parser.OFPActionOutput(out_port)]
                buckets.append(parser.OFPBucket(actions=actions))
                req = parser.OFPGroupMod(datapath=dp, command=ofp.OFPGC_ADD, type_=ofp.OFPGT_ALL,
                                         group_id=60, buckets=buckets)
                dp.send_msg(req)

                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                actions = [parser.OFPActionGroup(group_id=60)]
                self.add_flow(datapath=dp, priority=20, match=match, actions=actions,
                              idle_timeout=300, hard_timeout=600)

            # add flow table entry to the middle switch
            else:

                pre_switch = path[i - 1]
                next_switch = path[i + 1]

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

        for i in range(1, len(path2)):

            # current switch to add table flow entry
            cur_switch = path2[i]

            if i == len(path2) - 1:

                # from ipv4_src to ipv4_dst
                out_port = port_final
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

                # from ipv4_dst to ipv4_src
                pre_switch = path2[i - 1]
                out_port = self.ss_link[(cur_switch, pre_switch)][0]
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(eth_type=0x800, ipv4_src=ipv4_dst, ipv4_dst=ipv4_src)
                self.add_flow(self.datapath[cur_switch], 20, match, actions, 300, 600)

            # add flow table entry to the middle switch
            else:

                pre_switch = path2[i - 1]
                next_switch = path2[i + 1]

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

        # send the packet to the first switch
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out_port = port_begin
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=msg.datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        msg.datapath.send_msg(out)
```



如果代码出现问题，欢迎在评论区指出，或者直接 QQ 联系我

哈哈
