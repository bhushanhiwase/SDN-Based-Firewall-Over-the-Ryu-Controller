# *** CMPE-210 SDN & NFV Class Project ***
#  ** SDN Based Firewall Application Using RYU controller**
#   * Author: Bhushan Hiwase (SJSU ID: 014511445)*

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import tcp
import csv


class Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)  
    # This function Extracts the Switch (Datapath) information needed for the forwarding decisions  
    def switch_features_handler(self, ev):                                 
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

    # The following function Sends the modified Non-Drop flow rules to the Switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):                                      
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,                                     # This line decides the Forwarding actions based on the Port numbers     
                                             actions)]
        if buffer_id:                                                                                         # We check buffer ID if the packet entry is already in queue
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)                                            # This is the Flow Rules with Match and Actions sent to the switch
        datapath.send_msg(mod)                                                                                 # This function sends the flowrule to the switch   
    
    # Following function Sends the Modified DROP flow rules to the Switch
    # In RYU control plane programming the Drop Action is same as sending no action
    def add_flow_DropAction(self, datapath, priority, match, actions, buffer_id=None):  
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]

        print(' **** Adding the Drop Rule ****')                                                                # This print statement tells user that the drop rules are getting added

        if buffer_id:                                                                                           # We check buffer ID if the packet entry is already in queue
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    )                                                                           # This is the Flow Rules with Match and No Action sent to the switch
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,                                       # Here in this parser.OFPFlowmod method we are not providing any action
                                    match=match,)                                                               # Not adding any action field is same as saying add DROP action                             
        datapath.send_msg(mod)                                                                                  # This function sends the flowrule to the switch

    
    # If the Switch cannot forward the packet on immediate basis, then we need a Buffer to store packet temporarly, 
    # to avoid link congestion.The following lines of code checks if packet is present in the buffer with Buffer_ID 
    # If buffer is present, then it sends that buffer packet first.. This ensures that previoius packet was sent and link is free
    # The OFP_NO_BUFFER indicates that there is no buffer id / buffer and thus take normal actions

    # checks if buffer or not and takes drop action
    def CheckBufferDrop(self, match, datapath, actions, BufferId, msg, ofproto):                                    
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:                                                            # Check if the buffer ID is present            
            self.add_flow_DropAction(datapath, 1, match, actions, BufferId)                                   # If the Buffer Id is present then provide it to the add_flowDropaction()
            return
        else:
            self.add_flow_DropAction(datapath, 1, match, actions)                                              # After checking the buffer the data is sent to add_flow_DropAction which
                                                                                                               # which sends drop action to the switch

    # checks if buffer or not and takes Allow action                                                                             
    def CheckBufferAllow(self, match, datapath, actions, BufferId, msg, ofproto):                                    
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, BufferId)
            return
        else:
            self.add_flow(datapath, 1, match, actions) 


    # The function handels the Packet_in_event. When switch cannot find any action for a flow
    # it by default sends this packet to the controller, The EventOFPPacketIN object looks for
    # such entries and as soon as it finds it passes this data to our function _packet_in_handler
    # This function then parse the important info about the packet like protocol, SRC, DEST which helps
    #us to compare the ACL and Install the Firewall Rules                          

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):                                                         
        if ev.msg.msg_len < ev.msg.total_len:                                                                   # check if the message length is below allowed length
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg                            
        datapath = msg.datapath                                                                                 # Extracts the switch info and tells from where we recived the packet
        ofproto = datapath.ofproto                                                                              # Parse all the protocol Information        
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']                                                                          # Finds the Input port Information
        BufferId = msg.buffer_id

        pkt = packet.Packet(msg.data)                                                                           # we store the packet information in the variable called pkt
        eth = pkt.get_protocols(ethernet.ethernet)[0]                                                           # eth variable tells the Ehternt Protocol of the variable

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:                                                          # This line ensures that we ignore the LLDP packets 
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id                                                                                      # Extracts the datapath ID information
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)                                      # This line prints the data that we have recieved on the controller screen

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]                                                               # if entry is present in mac to port DPID then do this
        else:
            out_port = ofproto.OFPP_FLOOD                                                                        # Creates the output action saying flood the packet
        actions = [parser.OFPActionOutput(out_port)]                                                             # This line creates the action variable which would be sent by default 

        # We are reading the csv data from the files named Entries.csv 
        # After reading the information we save it in the form of list for next comparision
        with open('Entries.csv', 'r') as csv_file:            
            csv_reader = csv.reader(csv_file)
            global lst
            data = []                                                                                            # This contains all the data in each line of csv file (some of it is not needed)
            lst = []                                                                                             # This is the furbished list that contains list of only useful data fields for comparision
                                                                                                                 # the list variable contains [source_IP, Destination_IP or Port, and Blocking service]              
            for line in csv_reader:
                data.append(line)                                                                                # reads and put all the data in a line to a list
            for i in range(1, len(data)):                                                                        # we iteterate through all the items in the list to extract the desired fields only 
                lst.append([data[i][1], data[i][2], data[i][3]])                                                 # This line selects only three fields inportant for our analysis
                                                                                                                 # These three fields are [src_Ip, dest_IP/port, Blocked service]

        # *** Main Logic of Firewall Application Begins here *** #

        # When the operation is not is flooding mode (meaning switch knows the destination path) then we implement our logic of Firewall
        if out_port != ofproto.OFPP_FLOOD:
            # check IP Protocol and create a match parameter needed to provide in the send flow function
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)                                                                            # Here we extract the Ip address of ipv4 protocol
                srcip = ip.src                                                                                              # gives you the source IP of the the packet_in, packet
                dstip = ip.dst                                                                                              # Gives you the Destination IP of the the packet_in, packet
                protocol = ip.proto                                                                                         # This parameter contains all the info about the upper layer IP protocols
                # in order to match the ACL field in the csv with the current packet field
                # we run a for loop on the ACL parameters saved inside of the list 
                for i in lst:                               
                    word = i[2]                                                                    # We create a variable named word in which we save the Ptotocol field to match with the packet_in, packet        
                    # Following checks if the blocking should be based on IP address or the Port Number
                    # The Ip address is always greater that length=7 and Port number is lesser than length=5    
                    if len(i[0]) >= 7:                                                                 
                        # This Block is executed when the packet fields (source Ip and dest IP)
                        #  matches with user ACL blocked list, Also the match field for each
                        # protocol will be different, thus we create match based on protocols (ICMP, TCP, UDP)
                        if srcip == i[0] and dstip == i[1]:                                                                # comparing if the packet_in packet's IP matches with user desired ACL IP's
                            # If the blocking protocol parameter inputted by user is ICMP Protocol
                            if protocol == in_proto.IPPROTO_ICMP and word == 'ICMP':                                       # check the protocol of obtained packet is ICMP, and block request is also ICMP
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                         ipv4_dst=dstip, ip_proto=protocol)
                                self.CheckBufferDrop(match, datapath, actions, BufferId, msg, ofproto)                     # Function checks the buffer status and calls drop or no drop flow send function
                                break                                                                                      # if match found then exit the for loop

                            #  If the  blocking protocol parameter inputted by user is TCP Protocol
                            elif protocol == in_proto.IPPROTO_TCP and word == 'TCP':                                       # check the protocol of obtained packet is TCP and word is also TCP
                                tcp_packet = pkt.get_protocol(tcp.tcp)
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                        ipv4_dst=dstip, ip_proto=protocol, tcp_src=tcp_packet.src_port,
                                                        tcp_dst=tcp_packet.dst_port,)
                                self.CheckBufferDrop(match, datapath, actions, BufferId, msg, ofproto)                       # Function checks the buffer status and calls drop flow send function
                                break                                                                                        # if match found then exit the for loop  
                                
                            #  If the protocol inputted by user is UDP Protocol 
                            elif protocol == in_proto.IPPROTO_UDP and word == 'UDP':                                         # check if the word requested by user is TCP and packet is also TCP
                                udp_packet = pkt.get_protocol(udp.udp)
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                        ipv4_dst=dstip, ip_proto=protocol, udp_src=udp_packet.src_port,
                                                        udp_dst=udp_packet.dst_port,)
                                self.CheckBufferDrop(match, datapath, actions, BufferId, msg, ofproto)                        # Function checks the buffer status and calls drop flow send function
                                break                                                                                         # if match found then exit the for loop  

                    elif len(i[0]) <= 5:                                                                                     # Port blocking as port number string length is lesser than 5 (0 < port# < 65536)
                        tcp_packet = pkt.get_protocol(tcp.tcp)                                                               # captures the TCP packet as port number is present only for TCP and UDP
                        udp_packet = pkt.get_protocol(udp.udp)                                                               # captures the UDP packet

                        if word == 'TCP' and tcp_packet is not None:                                                         # we make sure that the captured TCP packet is not empty (not None)
                            if tcp_packet.dst_port == int(float(i[1])):                                                      # tcp_packet.dst_port is in integer form only (not a string)
                                                                                                                             # Block traffic from any source port to the given destination port
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                       ipv4_dst=dstip, ip_proto=protocol, tcp_src=tcp_packet.src_port, 
                                                       tcp_dst=tcp_packet.dst_port,)
                                self.CheckBufferDrop(match, datapath, actions, BufferId, msg, ofproto)                       # Function checks the buffer status and calls drop flow send function
                                break
                            
                        elif word == 'UDP' and udp_packet is not None:  
                            if udp_packet.dst_port == int(float(i[1])):                                                      # udp_packet.dst_port is on form integer
                                                                                                                             # Block traffic from any source port to the given destination port
                                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                        ipv4_dst=dstip, ip_proto=protocol, udp_src=udp_packet.src_port,
                                                        udp_dst=udp_packet.dst_port,)
                                self.CheckBufferDrop(match, datapath, actions, BufferId, msg, ofproto)                       # Function checks the buffer status and calls drop flow send function
                                break

                # This block is executed when the capture packet fields do not match with user inputted ACL parameters           
                else:
                #If the protocol inputted by user is ICMP with no match from csv file
                    if protocol == in_proto.IPPROTO_ICMP:
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip,
                                                ipv4_dst=dstip, ip_proto=protocol)
                        self.CheckBufferAllow(match, datapath, actions, BufferId, msg, ofproto)                             # Function checks the buffer status and calls No drop flow send function

                    #  If the protocol inputted by user is TCP Protocol with no match from csv file
                    elif protocol == in_proto.IPPROTO_TCP:
                        tcp_packet = pkt.get_protocol(tcp.tcp)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip,
                                                ip_proto=protocol,tcp_src=tcp_packet.src_port,
                                                tcp_dst=tcp_packet.dst_port,)
                        self.CheckBufferAllow(match, datapath, actions, BufferId, msg, ofproto)                             # Function checks the buffer status and calls No drop flow send function

                    #  If the protocol inputted by user is UDP Protocol with no match from csv file
                    elif protocol == in_proto.IPPROTO_UDP:
                        udp_packet = pkt.get_protocol(udp.udp)
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip,
                                                ip_proto=protocol, udp_src=udp_packet.src_port, 
                                                udp_dst=udp_packet.dst_port,) 
                        self.CheckBufferAllow(match, datapath, actions, BufferId, msg, ofproto)                             # Function checks the buffer status and calls No drop flow send function   
                


        # This line handels the packets which are of nature flood_type takes actions based on the action parameter in line 133
        # THis line also saves us from repeating the above logic on same packet treated already, as flooding packets
        # should be sent with default action in order for switches to learn the ports
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)                              