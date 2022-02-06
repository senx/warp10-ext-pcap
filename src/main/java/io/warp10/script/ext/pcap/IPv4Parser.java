//
//  Copyright 2018-2022  SenX S.A.S.
//

package io.warp10.script.ext.pcap;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;

public class IPv4Parser {

  public static final Long IPV4_ICMP = 1L;
  public static final Long IPV4_TCP = 6L;
  public static final Long IPV4_UDP = 17L;

  public static int parse(Map<String,Object> fields, byte[] data, int offset, int len) {
    if (offset < 0) {
      return offset;
    }

    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);

    int offset_orig = offset;

    try {
      long version = (long) bb.get() & 0xffL;
      offset += 1;

      fields.put(Fields.IP_VERSION, (long) ((version & 0xf0L) >> 4));
      fields.put(Fields.IPV4_IHL, (long) (version & 0xfL));

      long tos = bb.get() & 0xff;
      offset += 1;

      fields.put(Fields.IPV4_TOS, tos);

      long total_length = bb.getShort() & 0xffff;
      offset += 2;

      fields.put(Fields.IPV4_LENGTH, total_length);

      long identification = bb.getShort() & 0xffff;
      offset += 2;
      fields.put(Fields.IPV4_IDENTIFICATION, identification);

      long flagsfo = bb.getShort() & 0xffff;
      offset += 2;
      fields.put(Fields.IPV4_FLAGS, (flagsfo  >> 13) & 0x7);
      fields.put(Fields.IPV4_FLAGS_D, (flagsfo & 0x40) >> 14);
      fields.put(Fields.IPV4_FLAGS_M, (flagsfo & 0x20) >> 13);
      fields.put(Fields.IPV4_FRAGMENT_OFFSET, (flagsfo & 0x17ff));

      int ttl = bb.get() & 0xff;
      offset += 1;
      fields.put(Fields.IPV4_TTL, (long) ttl);

      int proto = bb.get() & 0xff;
      offset += 1;
      fields.put(Fields.IPV4_PROTOCOL, (long) proto);

      int checksum = bb.getShort() & 0xffff;
      offset += 2;
      fields.put(Fields.IPV4_HEADER_CHECKSUM, (long) checksum);

      int srcaddr = bb.getInt();
      offset += 4;
      fields.put(Fields.IPV4_SRC, "" + ((srcaddr >> 24) & 0xff) + "." + ((srcaddr >> 16) & 0xff) + "." + ((srcaddr >> 8) & 0xff) + "." + (srcaddr & 0xff));

      int dstaddr = bb.getInt();
      offset += 4;
      fields.put(Fields.IPV4_DST, "" + ((dstaddr >> 24) & 0xff) + "." + ((dstaddr >> 16) & 0xff) + "." + ((dstaddr >> 8) & 0xff) + "." + (dstaddr & 0xff));

      //
      // Extract the IP Options
      // @see http://www.tcpipguide.com/free/t_IPDatagramOptionsandOptionFormat.htm
      //

      int ihl = ((Number) fields.get(Fields.IPV4_IHL)).intValue();

      if (ihl > 5) {
        long optionType = bb.get() & 0xffL;
        offset += 1;
        fields.put(Fields.IPV4_OPTION_COPIED, (optionType & 0x80L) >> 7);
        fields.put(Fields.IPV4_OPTION_CLASS, (optionType & 0x60L) >> 5);
        fields.put(Fields.IPV4_OPTION_NUMBER, optionType & 0x1fL);

        int optionLength = bb.get() & 0xff;
        offset += 1;

        fields.put(Fields.IPV4_OPTION_LENGTH, (long) optionLength);

        if (optionLength > 2) {
          fields.put(Fields.IPV4_OPTION_DATA, Arrays.copyOfRange(data, offset, offset + optionLength - 3));
          offset += optionLength - 2;
        }
      }

      if (offset - offset_orig < len) {
        fields.put(Fields.IPV4_PAYLOAD, Arrays.copyOfRange(data, offset, offset_orig + len));
        return offset;
      } else {
        return -1;
      }
    } catch (ArrayIndexOutOfBoundsException|BufferUnderflowException bue) {
      fields.put(Fields.IPV4_UNDERFLOW, true);
    }

    return -1;
  }
}
