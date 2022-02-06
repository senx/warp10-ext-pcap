//
//  Copyright 2018-2022  SenX S.A.S.
//

package io.warp10.script.ext.pcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;

public class TCPParser {
  public static int parse(Map<String,Object> fields, byte[] data, int offset, int len) {
    if (offset < 0) {
      return offset;
    }

    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);

    int payload_offset = -1;

    try {
      int src = bb.getShort() & 0xffff;
      fields.put(Fields.TCP_SRC, (long) src);
      int dst = bb.getShort() & 0xffff;
      fields.put(Fields.TCP_DST, (long) dst);
      int seqno = bb.getInt();
      fields.put(Fields.TCP_SEQNO, (long) seqno);
      int ack = bb.getInt();
      fields.put(Fields.TCP_ACK, (long) ack);
      int offset_reserved = bb.get() & 0xff;
      fields.put(Fields.TCP_OFFSET, (long) (offset_reserved >> 4));
      int flags = bb.get() & 0xff;
      fields.put(Fields.TCP_FLAGS, (long) flags);
      fields.put(Fields.TCP_FLAGS_C, (long) ((flags & 0x80) >> 7));
      fields.put(Fields.TCP_FLAGS_E, (long) ((flags & 0x40) >> 6));
      fields.put(Fields.TCP_FLAGS_U, (long) ((flags & 0x20) >> 5));
      fields.put(Fields.TCP_FLAGS_A, (long) ((flags & 0x10) >> 4));
      fields.put(Fields.TCP_FLAGS_P, (long) ((flags & 0x08) >> 3));
      fields.put(Fields.TCP_FLAGS_R, (long) ((flags & 0x04) >> 2));
      fields.put(Fields.TCP_FLAGS_S, (long) ((flags & 0x02) >> 1));
      fields.put(Fields.TCP_FLAGS_F, (long) (flags & 0x01));

      int window = bb.getShort() & 0xffff;
      fields.put(Fields.TCP_WINDOW, (long) window);
      int checksum = bb.getShort() & 0xffff;
      fields.put(Fields.TCP_CHECKSUM, (long) checksum);
      int urgent = bb.getShort() & 0xffff;
      fields.put(Fields.TCP_URGENT, (long) urgent);

      if (offset_reserved >> 4 > 5) {
        fields.put(Fields.TCP_OPTIONS, Arrays.copyOfRange(data, bb.position(), bb.position() + ((offset_reserved >> 4) - 5) * 4 - 1));
      }

      if (offset + ((offset_reserved >> 4) - 5) * 4 < len) {
        fields.put(Fields.TCP_PAYLOAD, Arrays.copyOfRange(data, offset + ((offset_reserved >> 4) - 5) * 4, offset + len));
        payload_offset = offset + ((offset_reserved >> 4) - 5) * 4;
      }
    } catch (ArrayIndexOutOfBoundsException|BufferUnderflowException bue) {
      fields.put(Fields.TCP_UNDERFLOW, true);
    }

    return payload_offset;
  }
}
