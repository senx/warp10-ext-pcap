package io.warp10.script.ext.pcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;

public class UDPParser {
  public static int parse(Map<String,Object> fields, byte[] data, int offset, int len) {
    if (offset < 0) {
      return offset;
    }

    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);

    try {
      int srcport = bb.getShort() & 0xffff;
      fields.put(Fields.UDP_SRC, (long) srcport);
      int dstport = bb.getShort() & 0xffff;
      fields.put(Fields.UDP_DST, (long) dstport);
      int length = bb.getShort() & 0xffff;
      fields.put(Fields.UDP_LEN, (long) length);
      int checksum = bb.getShort() & 0xffff;
      fields.put(Fields.UDP_CHECKSUM, (long) checksum);

      if (length > 8) {
        fields.put(Fields.UDP_PAYLOAD, Arrays.copyOfRange(data, bb.position(), offset + len));
        return bb.position();
      } else {
        return -1;
      }
    } catch (BufferUnderflowException bue) {
      fields.put(Fields.UDP_UNDERFLOW, true);
    }

    return -1;
  }
}
