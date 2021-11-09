package io.warp10.script.ext.pcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;

public class EthernetParser {

  public static final Long ETHERNET_V2 = 0x800L;

  public static int parse(Map<String,Object> fields, byte[] data, int offset, int len) {
    if (offset < 0) {
      return offset;
    }

    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);

    int offset_orig = offset;

    //
    // Extract MAC addresses
    //

    try {
      fields.put(Fields.ETHER_MAC_DST, new String(Hex.encodeHex(Arrays.copyOfRange(data, offset, offset + 5))));
      offset += 6;

      fields.put(Fields.ETHER_MAC_SRC, new String(Hex.encodeHex(Arrays.copyOfRange(data, offset, offset + 5))));
      offset += 6;

      bb.position(offset);
      int type = bb.getShort() & 0xffff;
      offset += 2;

      //
      // 802.1Q frame
      // @see http://en.wikipedia.org/wiki/IEEE_802.1Q
      //

      if (type == 0x8100) {
        // Extract the Tag Control Identifier
        bb.position(offset);

        int tci = bb.getShort() & 0xffff;
        offset += 2;

        fields.put(Fields.ETHER_PCP, (long) ((tci & 0xe000) >> 13));
        fields.put(Fields.ETHER_DE, (long) ((tci & 0x1000) >> 12));
        fields.put(Fields.ETHER_VID, (long) (tci & 0x7ff));

        type = bb.getShort() & 0xffff;
        offset += 2;
      }

      fields.put(Fields.ETHER_TYPE, (long) type);

      if (type <= 1500) {
        //
        // 802.3 frame
        //

        fields.put(Fields.ETHER_LEN, (long) type);

        //
        // Extract 802.2 LLC Header
        //

        bb.position(offset);
        int dsap = bb.get() & 0xff;
        fields.put(Fields.ETHER_DSAP, (long) dsap);
        offset += 1;

        int ssap = bb.get() & 0xff;
        fields.put(Fields.ETHER_SSAP, (long) ssap);
        offset += 1;
      } else if (type >= 1536) {
        //
        // Ethernet v2
        //

        fields.put(Fields.ETHER_PAYLOAD, Arrays.copyOfRange(data, offset, offset_orig + len));
      } else {
        //
        // Undefined
        //
      }
    } catch (BufferUnderflowException bue) {
      fields.put(Fields.ETHER_UNDERFLOW, true);
    }

    return offset;
  }
}
