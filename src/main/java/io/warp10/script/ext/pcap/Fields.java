package io.warp10.script.ext.pcap;

public class Fields {
  
  //
  // PCAP Global Header
  //
  
  public static final String PCAP_MAGIC_NUMBER = "pcap.magic_number";
  public static final String PCAP_NATIVE = "pcap.native";
  public static final String PCAP_NANOS = "pcap.nanos";
  public static final String PCAP_VERSION_MAJOR = "pcap.version_major";
  public static final String PCAP_VERSION_MINOR = "pcap.version_minor";
  public static final String PCAP_THISZONE = "pcap.thiszone";
  public static final String PCAP_SIGFIGS = "pcap.sigfigs";
  public static final String PCAP_SNAPLEN = "pcap.snaplen";
  public static final String PCAP_NETWORK = "pcap.network";

  //
  // PCAP Record Header
  //
  
  public static final String PCAP_TS_SEC = "pcap.ts_sec";
  public static final String PCAP_TS_USEC = "pcap.ts_usec";
  public static final String PCAP_TS_NSEC = "pcap.ts_nsec";
  public static final String PCAP_INCL_LEN = "pcap.incl_len";
  public static final String PCAP_ORIG_LEN = "pcap.orig_len";
  // Timestamp in the platform's time units
  public static final String PCAP_TS = "pcap.ts";
  //
  // Ethernet framce
  //
  
  public static final String ETHER_MAC_SRC = "ether.src";
  public static final String ETHER_MAC_DST = "ether.dst";
  public static final String ETHER_TYPE = "ether.type";
  public static final String ETHER_PCP = "ether.pcp";
  public static final String ETHER_DE = "ether.de";
  public static final String ETHER_VID = "ether.vid";
  public static final String ETHER_LEN = "ether.len";
  public static final String ETHER_DSAP = "ether.dsap";
  public static final String ETHER_SSAP = "ether.ssap";
  public static final String ETHER_PAYLOAD = "ether.payload";
  public static final String ETHER_UNDERFLOW = "ether.underflow";
  
  //
  // IP Datagram
  //
  
  public static final String IP_VERSION = "ip.version";
  public static final String IPV4_IHL = "ipv4.ihl";
  public static final String IPV4_TOS = "ipv4.tos";
  public static final String IPV4_LENGTH = "ipv4.len";
  public static final String IPV4_IDENTIFICATION = "ipv4.id";
  public static final String IPV4_FLAGS = "ipv4.flags";
  public static final String IPV4_FLAGS_D = "ipv4.flags.d";
  public static final String IPV4_FLAGS_M = "ipv4.flags.m";
  public static final String IPV4_FRAGMENT_OFFSET = "ipv4.offset";
  public static final String IPV4_TTL = "ipv4.ttl";
  public static final String IPV4_PROTOCOL = "ipv4.proto";
  public static final String IPV4_HEADER_CHECKSUM = "ipv4.checksum";
  public static final String IPV4_SRC = "ipv4.src";
  public static final String IPV4_DST = "ipv4.dst";
  public static final String IPV4_OPTION_COPIED = "ipv4.opt.cpy";
  public static final String IPV4_OPTION_CLASS = "ipv4.opt.cls";
  public static final String IPV4_OPTION_NUMBER = "ipv4.opt.num";
  public static final String IPV4_OPTION_LENGTH = "ipv4.opt.len";
  public static final String IPV4_OPTION_DATA = "ipv4.opt.data";
  public static final String IPV4_PAYLOAD = "ipv4.payload";
  public static final String IPV4_UNDERFLOW = "ipv4.underflow";

  //
  // ICMP
  //
  
  public static final String ICMP_TYPE = "icmp.type";
  public static final String ICMP_CODE = "icmp.code";
  public static final String ICMP_CHECKSUM = "icmp.checksum";
  public static final String ICMP_INFO = "icmp.info";
  public static final String ICMP_UNDERFLOW = "icmp.underflow";

  //
  // TCP
  //
  
  public static final String TCP_SRC = "tcp.src";
  public static final String TCP_DST = "tcp.dst";
  public static final String TCP_SEQNO = "tcp.seqno";
  public static final String TCP_ACK = "tcp.ack";
  public static final String TCP_OFFSET = "tcp.offset";
  public static final String TCP_FLAGS = "tcp.flags";
  public static final String TCP_FLAGS_C = "tcp.flags.c";
  public static final String TCP_FLAGS_E = "tcp.flags.e";
  public static final String TCP_FLAGS_U = "tcp.flags.u";
  public static final String TCP_FLAGS_A = "tcp.flags.a";
  public static final String TCP_FLAGS_P = "tcp.flags.p";
  public static final String TCP_FLAGS_R = "tcp.flags.r";
  public static final String TCP_FLAGS_S = "tcp.flags.s";
  public static final String TCP_FLAGS_F = "tcp.flags.f";
  public static final String TCP_WINDOW = "tcp.window";
  public static final String TCP_CHECKSUM = "tcp.checksum";
  public static final String TCP_URGENT = "tcp.urgent";
  public static final String TCP_OPTIONS = "tcp.opt";
  public static final String TCP_PAYLOAD = "tcp.payload";
  public static final String TCP_UNDERFLOW = "tcp.underflow";

  //
  // UDP
  //
  
  public static final String UDP_SRC = "udp.src";
  public static final String UDP_DST = "udp.dst";
  public static final String UDP_LEN = "udp.len";
  public static final String UDP_CHECKSUM = "udp.checksum";
  public static final String UDP_PAYLOAD = "udp.payload";
  public static final String UDP_UNDERFLOW = "udp.underflow";
}
