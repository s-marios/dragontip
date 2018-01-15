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
from typing import Tuple, List, Set

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
        self.bridgemac = "";
        #macs as a list of bytes here
        self.uniquemacs : List[bytes] = [];
        self.parser : HTIPParser = HTIPParser();

        
    def periodic_test(self):
        woke = 0;
        while True:
            hub.sleep(5);
            woke += 1;
            print("#macs: {}".format(len(self.forwardingTable)));
            #print("mac list: {}".format("".join(map(self.forwardingTable.values()))));
            print("macs: \n{}".format("\t".join(self.forwardingTable.keys())));
            self.periodic_packet();

        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg : ofproto_v1_0_parser.OFPPacketIn = ev.msg;
        dp : Datapath = msg.datapath
        proto = dp.ofproto
        parser = dp.ofproto_parser
        inpkt : Packet = packet.Packet(msg.data);
        eth = inpkt.get_protocol(ethernet.ethernet);
        src = eth.src;
        if src in self.forwardingTable:
            print("*", end="");
        else:
            print("new mac: " + src);
            print("number of macs: {} \n".format(len(self.forwardingTable)));
        self.forwardingTable[src] = msg.in_port;
        #flooding the packet to all the ports we know
        actions = [parser.OFPActionOutput(proto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath = dp, buffer_id = msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = msg.data)
        dp.send_msg(out);

        
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
        print("\nOUT OF SWITCH CONNECT\n");
        print("hw_addr")
        #get mac info
        mac, count, uniquemacs = self.getMacInformation(ports)
        print("Mac: " + mac + ", count number: " + str(count));
        self.bridgemac = mac;
        self.uniquemacs = [bytes.fromhex(amac.replace(':','')) for amac in uniquemacs];
        #finally setup an HTIP parser.
        self.parser.mac = self.bridgemac;

        
    def getMacInformation(self, ports) -> Tuple[str, int, Set[str]]:
        #populate the mac dictionary with the counts of macs
        macs = {};
        for port in ports:
            if port.hw_addr in macs:
                macs[port.hw_addr] += 1;
            else:
                macs[port.hw_addr] = 1;
        #find the mac with the max instance count
        count : int = 0;
        result : str = "";
        for mac in macs.keys():
            if macs[mac] > count:
                count = macs[mac];
                result = mac;
        return result, count, set(macs.keys());

        
    def periodic_packet(self):
        if self.dp is None:
            return
        #pkt : Packet = self.makeTestLLDP();
        #setup subtype 3 here.
        self.parser.macs = self.uniquemacs;
        pkt : Packet = self.parser.makeHTIP();

        print("4")
        actions = [self.dp.ofproto_parser.OFPActionOutput(self.dp.ofproto.OFPP_FLOOD)];
        print("5")
        out = self.dp.ofproto_parser.OFPPacketOut(
            datapath = self.dp,  buffer_id = self.dp.ofproto.OFP_NO_BUFFER, in_port=OFPP_NONE,
            actions=actions, data=pkt);
        print("6")
        self.dp.send_msg(out);
        print("\nSent Stuff!\n");

        
    def makeTestLLDP(self) -> packet: 
        pkt : Packet = packet.Packet();
        eth : ethernet.ethernet = ethernet.ethernet(ethertype = 0x88cc);
        eth.src = self.bridgemac;
        eth.dst = 'FF:FF:FF:FF:FF:FF';
        pkt.add_protocol(eth);
        tlvs : List = [];
        chassis = ChassisID(subtype=ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id = b'muh switch');
        tlvs.append(chassis);
        portid : PortID = PortID(subtype= PortID.SUB_LOCALLY_ASSIGNED, port_id=b'\x09');
        tlvs.append(portid);
        ttl : TTL = TTL(ttl=1);
        tlvs.append(ttl);
        end : End = End();
        tlvs.append(end);
        proto_lldp : lldp = lldp(tlvs);
        pkt.add_protocol(proto_lldp);
        pkt.serialize();
        return pkt;
        
    
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
        self._mac : str = "";
        self._macs : List [bytes] = [bytes.fromhex("DEADBEEFCAFE"), bytes.fromhex("AAAABBBBCCCC")];
        
    @property
    def mac(self):
        return self._mac;
    
    @mac.setter
    def mac(self, mac : str):
        self._mac = mac;

    @property
    def macs(self):
        return self._macs;
    
    @macs.setter
    def macs(self, macs : List[str]):
        self._macs = macs;
        
    def makeHTIP(self) -> bytearray:

        # TODO what is our own mac address? some datapath structure has it?j
        pkt : Packet = packet.Packet();
        # currently we're doing broadcasts
        eth : ethernet.ethernet = ethernet.ethernet(ethertype=0x88CC);
        eth.src = self.mac;
        eth.dst = 'FF:FF:FF:FF:FF:FF';
        pkt.add_protocol(eth);
        
        tlvs : List = [];
        # create our htip message here
        # first standard LLDP things

        # chasis id must be mac address
        strippedmac : str = self.mac.replace(':', '');
        chassis = ChassisID(subtype=ChassisID.SUB_MAC_ADDRESS , chassis_id=bytes.fromhex(strippedmac));
        tlvs.append(chassis);
        
        # port id is implementation specific. Let's grab the port we're going to send it out from
        portid : PortID = PortID(subtype=PortID.SUB_LOCALLY_ASSIGNED, port_id=b'\x09');
        tlvs.append(portid);
        
        # ttl is implementation specific. However, let's think about this.
        #ttl : TTL = TTL(ttl=255);
        tlvs.append(TTL(ttl=255));
        
        #htipType : OrganizationallySpecific = self.makeHTIPType();
        tlvs.append(self.makeHTIPType());
        
        #add the rest
        tlvs.append(self.makeHTIPMakerCode());
        tlvs.append(self.makeHTIPModelName());
        tlvs.append(self.makeHTIPModelNumber());
        tlvs.append(self.makeHTIPMacList());

        # outro
        end : End = End();
        tlvs.append(end);

        proto_lldp : lldp = lldp(tlvs);
        pkt.add_protocol(proto_lldp);
        
        pkt.serialize();
        return pkt;

    
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