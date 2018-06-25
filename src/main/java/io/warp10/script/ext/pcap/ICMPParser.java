package io.warp10.script.ext.pcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;

public class ICMPParser {
  public static int parse(Map<String, Object> fields, byte[] data, int offset, int len) {
    if (offset < 0) {
      return offset;
    }
    
    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);
    
    try {
      int type = bb.get() & 0xff;
      fields.put(Fields.ICMP_TYPE, type);
      int code = bb.get() & 0xff;
      fields.put(Fields.ICMP_CODE, code);
      int checksum = bb.getShort() & 0xffff;
      fields.put(Fields.ICMP_CHECKSUM, checksum);
      int info = bb.getInt();
      fields.put(Fields.ICMP_INFO, info);
    } catch (BufferUnderflowException bue) {
      fields.put(Fields.ICMP_UNDERFLOW, true);
    }
    
    return -1;

  }
}
