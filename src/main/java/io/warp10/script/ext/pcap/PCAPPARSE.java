package io.warp10.script.ext.pcap;

import java.util.HashMap;
import java.util.Map;

import io.warp10.script.NamedWarpScriptFunction;
import io.warp10.script.WarpScriptException;
import io.warp10.script.WarpScriptStack;
import io.warp10.script.WarpScriptStackFunction;

public class PCAPPARSE extends NamedWarpScriptFunction implements WarpScriptStackFunction {
  public PCAPPARSE(String name) {
    super(name);
  }

  @Override
  public Object apply(WarpScriptStack stack) throws WarpScriptException {

    Object top = stack.pop();

    if (!(top instanceof byte[])) {
      throw new WarpScriptException(getName() + " expects a byte array containing pcap data on top of the stack.");
    }

    byte[] pkt = (byte[]) top;

    top = stack.pop();

    if (!(top instanceof byte[])) {
      throw new WarpScriptException(getName() + " expects a byte array containing a pcap record header below the pcap data.");
    }

    byte[] pcaprh = (byte[]) top;

    top = stack.pop();

    if (!(top instanceof byte[])) {
      throw new WarpScriptException(getName() + " expects a byte array containing a pcap global header below the pcap record header.");
    }

    byte[] pcapgh = (byte[]) top;

    Map<String,Object> fields = new HashMap<String,Object>();

    int offset = 0;
    int len = 24;

    PCapParser.parseGlobalHeader(fields, pcapgh, offset, len);

    offset = 0;
    len = 16;
    PCapParser.parseRecordHeader(fields, pcaprh, offset, len);

    offset = 0;
    len = pkt.length - offset;

    if (PCapParser.DLT_EN10MB.equals(fields.get(Fields.PCAP_NETWORK))) {
      offset = EthernetParser.parse(fields, pkt, offset, len);

      if (EthernetParser.ETHERNET_V2.equals(fields.get(Fields.ETHER_TYPE))) {
        offset = IPv4Parser.parse(fields, pkt, offset, pkt.length - offset);

        if (IPv4Parser.IPV4_TCP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
          offset = TCPParser.parse(fields, pkt, offset, pkt.length - offset);
        } else if (IPv4Parser.IPV4_UDP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
          offset = UDPParser.parse(fields, pkt, offset, pkt.length - offset);
        } else if (IPv4Parser.IPV4_ICMP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
          offset = ICMPParser.parse(fields, pkt, offset, pkt.length - offset);
        }
      } else {
        if (null != fields.get(Fields.ETHER_TYPE)) {
          int type = ((Number) fields.get(Fields.ETHER_TYPE)).intValue();

          if (type <= 1500) { // 802.3
          } else if (type >= 1536) {
          }
        }
      }
    } else if (PCapParser.DLT_RAW.equals(fields.get(Fields.PCAP_NETWORK))) {
      //See https://www.tcpdump.org/linktypes.html
      offset = IPv4Parser.parse(fields, pkt, offset, len);

      if (IPv4Parser.IPV4_TCP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
        offset = TCPParser.parse(fields, pkt, offset, pkt.length - offset);
      } else if (IPv4Parser.IPV4_UDP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
        offset = UDPParser.parse(fields, pkt, offset, pkt.length - offset);
      } else if (IPv4Parser.IPV4_ICMP.equals(fields.get(Fields.IPV4_PROTOCOL))) {
        offset = ICMPParser.parse(fields, pkt, offset, pkt.length - offset);
      }
    }

    stack.push(fields);

    return null;
  }
}
