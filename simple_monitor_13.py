# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager

from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types



class SimpleMonitor13(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        #self.mac_to_port_num = {}
        self.ban_mac_to_port = {}
        self.counter = 0
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('Address                   '
                         'Port')
        self.counter = 0;
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            '''
            self.logger.info('%17s %8x',
                             stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             )
            '''
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                                ev.msg.datapath.id,
                                stat.match['in_port'], stat.match['eth_dst'],
                                stat.instructions[0].actions[0].port,
                                stat.packet_count, stat.byte_count)
            if stat.packet_count > 10 :
                '''
                self.logger.info('%016x %8x %17s %8x %8d %8d',
                                ev.msg.datapath.id,
                                stat.match['in_port'], stat.match['eth_dst'],
                                stat.instructions[0].actions[0].port,
                                stat.packet_count, stat.byte_count)
                '''
                msg = ev.msg
                datapath = msg.datapath
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                in_port = stat.match['in_port']
                eth_dst = stat.match['eth_dst']
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth_dst)
                inst = []
                #mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, 
                #                                    priority=1, match=match,
                #                                    )
                mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE,0,0,1,ofproto.OFPCML_NO_BUFFER,ofproto.OFPP_ANY,ofproto.OFPG_ANY,0,match,inst)
                dpid = datapath.id
                #self.ban_mac_to_port.setdefault(dpid, {})
                self.mac_to_port.setdefault(dpid, {})
                self.ban_mac_to_port.setdefault(dpid, {})

                print "***inport = ", in_port
                #self.ban_mac_to_port[dpid][in_port] = eth_dst
                #datapath.send_msg(mod)
                
                for dst in self.mac_to_port[dpid] :
                    out_port = self.mac_to_port[dpid][dst]
                    print "dst = ", dst
                   # print "out_port = ", 
                    #print "dst = ", dst, " out_port = ", out_port, " stat.instructions[0].actions[0].port = ",  stat.instructions[0].actions[0].port 
                    
                    if stat.instructions[0].actions[0].port == out_port :
                        self.ban_mac_to_port[dpid][dst] = in_port
                        print "dst = ", dst, " out_port = ", out_port, " stat.instructions[0].actions[0].port = ",  stat.instructions[0].actions[0].port 
                datapath.send_msg(mod)
                
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    #def _port_stats_reply_handler(self, ev):
    def _port_statusi_reply_handler(self, ev):
        body = ev.msg.body

       # self.logger.info('datapath         port     '
        #                 'rx-pkts  rx-bytes rx-error '
        #                 'tx-pkts  tx-bytes tx-error')
       # self.logger.info('---------------- -------- '
       #                  '-------- -------- -------- '
       #                  '-------- -------- --------')
        self.logger.info('SW id:%8x',ev.msg.datapath.id)
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('port:%8x',stat.port_no)
            self.logger.info('tx_packets:%8x',stat.tx_packets)
            self.logger.info('rx_packets:%8x',stat.rx_packets)
            self.logger.info(' ')
        #for stat in sorted(body, key=attrgetter('port_no')):
            #self.logger.info('port:%8x',stat.port_no,)
            #self.logger.info('tx_packets:%8x ',stat.rx_packets)
            #self.logger.info('rx_packets:%8x ',stat.tx_packets)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
            
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)


        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.ban_mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        if dst in self.ban_mac_to_port[dpid] :
            print "!!!!!!dst in ban_mac = ", dst, " self.ban_mac_to_port[dpid][dst] = ", self.ban_mac_to_port[dpid][dst], " in_port = ", in_port
            if self.ban_mac_to_port[dpid][dst] == in_port :
                print "dst in ban_mac = ", dst
                return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print "out_port = ", out_port
        else:
            out_port = ofproto.OFPP_FLOOD






        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

