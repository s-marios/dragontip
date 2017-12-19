'''
@author: Marios S.
'''

#import sys
from typing import Dict;
from ryu.base import app_manager;
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import MAIN_DISPATCHER;
from ryu.controller.handler import set_ev_cls;
from ryu.ofproto import ofproto_v1_0, ofproto_v1_0_parser;
from ryu.lib.packet import packet;
from ryu.lib.packet import ethernet;
from ryu.lib.packet.lldp import lldp, ChassisID, PortID, TTL, End,\
    OrganizationallySpecific
from ryu.controller.controller import Datapath;
from ryu.lib import hub
from ryu.ofproto.ofproto_v1_0 import OFPP_NONE

class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        #self.forwardingTable = Dict[str, str];
        self.forwardingTable = {};
        print("I'm alive!!");
        self.test_makeHTIPpacket();
        self.threads.append(hub.spawn(self.periodic_test));
        self.dp :Datapath = None;
        
    def periodic_test(self):
        woke = 0;
        while True:
            hub.sleep(5);
            woke += 1;
            print("#macs: {}".format(len(self.forwardingTable)));
            #print("mac list: {}".format("".join(map(self.forwardingTable.values()))));
            print("macs: \n{}".format("\t".join(self.forwardingTable.keys())));
            #self.periodic_packet();
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg : ofproto_v1_0_parser.OFPPacketIn = ev.msg;
        #print("in packet in ", end="");
        
        dp : Datapath = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        inpkt : Packet = packet.Packet(msg.data);
        eth = inpkt.get_protocol(ethernet.ethernet);
        

        src = eth.src;
        if src in self.forwardingTable:
            print("*", end="");
            #print("old mac: "+ src);
        else:
            print("new mac: " + src);
            print("number of macs: {} \n".format(len(self.forwardingTable)));
        #print("Mac:" + src);
        self.forwardingTable[src] = msg.in_port;
        #print("blah");
 
        #flooding the packet to all the ports we know
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        ofp_parser.OFPActionOutput
        out = ofp_parser.OFPPacketOut(
            datapath = dp, buffer_id = msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        dp.send_msg(out)
        #print(msg)
        
    @set_ev_cls(dpset.EventDP, MAIN_DISPATCHER)
    def switch_connect(self, ev):
        print("\n\n IN SWITCH CONNECT: \n\n");
        dp = ev.dp;
        enter = ev.enter;
        ports = ev.ports;
        
        if enter:
            print("switch connected!");
            self.dp = ev.dp;
        else :
            print("switch disconnected!");
        if dp is not None:
            print("not None dp");
            print("datapath ID: "+ str(dp.id));
        print("number of ports: " + str(len(ports)));
        print("port numbers: "  + "".join(map(str, ports)));
        #print("dp: " + dp);
        print("\nOUT OF SWITCH CONNECT\n");
        
    def periodic_packet(self):
        pkt : Packet = packet.Packet();
        eth : ethernet.ethernet = ethernet.ethernet(ethertype = 0x0800);
        eth.dst = 0xffffffff;
        pkt.add_protocol(eth);
        print("1")
        tlvs : List = [];
        chassis = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id = b'muh swi');
        tlvs.append(chassis);
        portid : PortID = PortID(subtype= PortID.SUB_LOCALLY_ASSIGNED, port_id=b'\x09');
        tlvs.append(portid);
        print("2")
        ttl : TTL = TTL(ttl=255);
        tlvs.append(ttl);
        end : End = End();
        tlvs.append(end);
        print("3")
        proto_lldp : lldp = lldp(tlvs);
        pkt.add_protocol(proto_lldp);
        pkt.serialize();
        print("4")
        actions = [self.dp.ofproto_parser.OFPActionOutput(self.dp.ofproto.OFPP_FLOOD, 0)];
        print("5")
        out = self.dp.ofproto_parser.OFPPacketOut(
            datapath = self.dp, buffer_id = 0xffffffff, in_port=OFPP_NONE,
            actions=actions, data=pkt);
        print("6")
        self.dp.send_msg(out);
        print("\nSent Stuff!\n");
    
    def test_makeHTIPpacket(self):
        pkt : Packet = packet.Packet();
        eth : ethernet.ethernet = ethernet.ethernet(ethertype = 0x0800);
        pkt.add_protocol(eth);
        
        #create all tlvs as necessary
        tlvs : List = [];
        chassis = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id = b'aaa bbb');
        tlvs.append(chassis);
        
        portid : PortID = PortID(subtype= PortID.SUB_LOCALLY_ASSIGNED, port_id=b'\x09');
        tlvs.append(portid);
        
        ttl : TTL = TTL(ttl=255);
        tlvs.append(ttl);
        
        orgspec : OrganizationallySpecific = OrganizationallySpecific(oui = b'\xE0\x27\x1A', subtype=1, info= bytes.fromhex('aaaa'));
        tlvs.append(orgspec);
        
        parser : HTIPParser = HTIPParser();

        htipType : OrganizationallySpecific = parser.makeHTIPType();
        tlvs.append(htipType);
        
        htipMakerCode : OrganizationallySpecific = parser.makeHTIPMakerCode();
        tlvs.append(htipMakerCode);
        
        htipModelName : OrganizationallySpecific = parser.makeHTIPModelName();
        tlvs.append(htipModelName);

        htipModelNumber : OrganizationallySpecific = parser.makeHTIPModelNumber();
        tlvs.append(htipModelNumber);
        
        htipmacs : OrganizationallySpecific = parser.makeHTIPMacList();
        tlvs.append(htipmacs);
        
        end : End = End();
        tlvs.append(end);

        proto_lldp : lldp = lldp(tlvs);
        #print(eth.serialize(bytearray(), None).hex());
        #print(proto_lldp.serialize(None, None).hex());

        pkt.add_protocol(proto_lldp);
        pkt.serialize();


        #just print the damn thing for now.
        print("hex: " + pkt.data.hex());
        print("text: " + pkt.data.decode("utf-8", "ignore" ));
        
class HTIPParser():
    '''
    classdocs
    
    This is supposed to be the main HTIP Packet creating/parsing class
    '''
    OUI : bytes = b'\xE0\x27\x1A';

    def __init__(self):
        '''
        Constructor
        '''
        self.htipType : str = "switch";
        self.htipTypeSubtype : int = 1;
        self.htipMakerCode : str = "MS";
        self.htipMakerCodeSubtype : int = 2;
        self.htipModelName : str = "MS switch";
        self.htipModelNameSubtype : int = 3;
        self.htipModelNumber : str = "HTIP SWITCH V0.01";
        self.htipModelNumberSubtype : int = 4;
        self.macs = [bytes.fromhex("DEADBEEFCAFE"), bytes.fromhex("AAAABBBBCCCC")];
        
    def makeHTIP(self, forwardingTable : Dict [str, str]) -> bytearray:

        # TODO what is our own mac address? some datapath structure has it?j
        pkt : Packet = packet.Packet();
        # currently we're doing broadcasts
        eth : ethernet.ethernet = ethernet.ethernet(ethertype=0x08CC);
        pkt.add_protocol(eth);
        
        tlvs : List = [];
        
        # create our htip message here
        # first standard LLDP things

        # chasis id must be mac address
        chassis = ChassisID(subtype=ChassisID.SUB_MAC_ADDRESS , chassis_id=bytes.fromhex('deadbeefbabe'));
        tlvs.append(chassis);
        
        # port id is implementation specific. Let's grab the port we're going to send it out from
        portid : PortID = PortID(subtype=PortID.SUB_LOCALLY_ASSIGNED, port_id=b'\x09');
        tlvs.append(portid);
        
        # ttl is implementation specific. However, let's think about this.
        ttl : TTL = TTL(ttl=255);
        tlvs.append(ttl);
        
        htipType : OrganizationallySpecific = self.makeHTIPType();
        tlvs.append(htipType);

        # outro
        end : End = End();
        tlvs.append(end);

        proto_lldp : lldp = lldp(tlvs);
        pkt.add_protocol(proto_lldp);
        
        pkt.serialize();
        return pkt.data;
    
    def makeHTIPType(self) -> OrganizationallySpecific:
        bytesinfo : bytearray = bytearray([self.htipTypeSubtype]);  # subtype 1
        bytesinfo.append(len(self.htipType));
        bytesinfo.extend(self.htipType.encode(encoding='utf_8', errors='strict'));

        tlv : OrganizationallySpecific = OrganizationallySpecific(oui=HTIPParser.OUI, subtype=1, info=bytesinfo);
        return tlv;

    def makeHTIPMakerCode(self) -> OrganizationallySpecific:
        bytesinfo = bytearray([self.htipMakerCodeSubtype]);
        bytesinfo.append(len(self.htipMakerCode));
        bytesinfo.extend(self.htipMakerCode.encode(encoding='utf_8', errors='strict'));

        tlv : OrganizationallySpecific = OrganizationallySpecific(oui=HTIPParser.OUI, subtype=1, info=bytesinfo);
        return tlv;

    def makeHTIPModelName(self) -> OrganizationallySpecific:
        bytesinfo = bytearray([self.htipModelNameSubtype]);
        bytesinfo.append(len(self.htipModelName));
        bytesinfo.extend(self.htipModelName.encode(encoding='utf_8', errors='strict'));

        tlv : OrganizationallySpecific = OrganizationallySpecific(oui=HTIPParser.OUI, subtype=1, info=bytesinfo);
        return tlv;

    def makeHTIPModelNumber(self) -> OrganizationallySpecific:
        bytesinfo = bytearray([self.htipModelNumberSubtype]);
        bytesinfo.append(len(self.htipModelNumber));
        bytesinfo.extend(self.htipModelNumber.encode(encoding='utf_8', errors='strict'));

        tlv : OrganizationallySpecific = OrganizationallySpecific(oui=HTIPParser.OUI, subtype=1, info=bytesinfo);
        return tlv;
    
    def makeHTIPMacList(self) -> OrganizationallySpecific:
        bytesinfo = bytearray([len(self.macs)]);
        bytesinfo.append(len(self.macs[0]));
        for x in self.macs:
            bytesinfo.extend(x);

        tlv : OrganizationallySpecific = OrganizationallySpecific(oui=HTIPParser.OUI, subtype=3, info=bytesinfo);
        return tlv;