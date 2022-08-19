package io.warp10.script.ext.pcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;

import io.warp10.continuum.store.Constants;

public class PCapParser {

  //
  // DataLinkTypes
  // @see http://www.tcpdump.org/linktypes.html
  //

  public static final Long DLT_EN10MB = 1L;
  public static final Long DLT_RAW = 101L;

  public static void parseGlobalHeader(Map<String,Object> fields, byte[] data, int offset, int len) {
    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);
    bb.order(ByteOrder.BIG_ENDIAN);

    // Extract the magic number
    int magic = bb.getInt();
    fields.put(Fields.PCAP_MAGIC_NUMBER, (long) magic & 0xFFFFFFFFL);

    if (0xa1b2c3d4 == magic) {
      fields.put(Fields.PCAP_NATIVE, true);
      fields.put(Fields.PCAP_NANOS, false);
    } else if (0xa1b23c4d == magic) {
      fields.put(Fields.PCAP_NATIVE, true);
      fields.put(Fields.PCAP_NANOS, true);
    } else if (0xd4c3b2a1 == magic) {
      fields.put(Fields.PCAP_NATIVE, false);
      bb.order(ByteOrder.LITTLE_ENDIAN);
      fields.put(Fields.PCAP_NANOS, false);
    } else if (0x4d3cb2a1 == magic) {
      fields.put(Fields.PCAP_NATIVE, false);
      bb.order(ByteOrder.LITTLE_ENDIAN);
      fields.put(Fields.PCAP_NANOS, true);
    }

    fields.put(Fields.PCAP_VERSION_MAJOR, (long) bb.getShort());
    fields.put(Fields.PCAP_VERSION_MINOR, (long) bb.getShort());
    fields.put(Fields.PCAP_THISZONE, (long) bb.getInt());
    fields.put(Fields.PCAP_SIGFIGS, (long) bb.getInt());
    fields.put(Fields.PCAP_SNAPLEN, (long) bb.getInt());
    fields.put(Fields.PCAP_NETWORK, (long) bb.getInt());
  }

  public static void parseRecordHeader(Map<String,Object> fields, byte[] data, int offset, int len) {
    ByteBuffer bb = ByteBuffer.wrap(data, offset, len);

    if (Boolean.TRUE.equals(fields.get(Fields.PCAP_NATIVE))) {
      bb.order(ByteOrder.BIG_ENDIAN);
    } else {
      bb.order(ByteOrder.LITTLE_ENDIAN);
    }

    int sec = bb.getInt();
    int usec = 0;
    int nsec = 0;

    fields.put(Fields.PCAP_TS_SEC, (long) sec);
    if (Boolean.TRUE.equals(fields.get(Fields.PCAP_NANOS))) {
      nsec = bb.getInt();
      fields.put(Fields.PCAP_TS_NSEC, (long) nsec);
    } else {
      usec = bb.getInt();
      fields.put(Fields.PCAP_TS_USEC, (long) usec);
    }

    long ts = (long) sec * Constants.TIME_UNITS_PER_S;
    if (usec > 0) {
      ts += usec / (Constants.NS_PER_TIME_UNIT / 1000);
    } else if (nsec > 0) {
      ts += nsec / Constants.NS_PER_TIME_UNIT;
    }
    fields.put(Fields.PCAP_TS, ts);
    fields.put(Fields.PCAP_INCL_LEN, (long) bb.getInt());
    fields.put(Fields.PCAP_ORIG_LEN, (long) bb.getInt());
  }
}
