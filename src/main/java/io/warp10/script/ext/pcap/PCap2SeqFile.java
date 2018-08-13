package io.warp10.script.ext.pcap;

import java.io.IOException;
import java.util.Arrays;
import java.util.EnumSet;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CreateFlag;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileContext;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Options.CreateOpts;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.SequenceFile;
import org.apache.hadoop.io.SequenceFile.CompressionType;
import org.apache.hadoop.io.SequenceFile.Metadata;
import org.apache.hadoop.io.compress.DefaultCodec;

/**
 * Converts a libpcap file into a SequenceFile of records
 */
public class PCap2SeqFile {
  
  
  public static void convert(Configuration conf, Path inPath, Path outPath) throws IOException {
    FileContext fc = FileContext.getFileContext(conf);
    FileSystem fs = inPath.getFileSystem(conf);
    
    FSDataInputStream in = fs.open(inPath);

    EnumSet<CreateFlag> flags = EnumSet.of(CreateFlag.CREATE);
    flags.add(CreateFlag.OVERWRITE);
    
    SequenceFile.Writer sfwriter = SequenceFile.createWriter(fc,
        conf,
        outPath,
        BytesWritable.class,
        BytesWritable.class,
        CompressionType.BLOCK,
        new DefaultCodec(),
        new Metadata(),
        flags,
        CreateOpts.blockSize(1024 * 100));
        
    boolean eof = false;
    
    //
    // Read Global pcap header (24 bytes)
    //

    byte[] globalHeader = new byte[24];
    int len = in.read(globalHeader, 0, globalHeader.length);
    
    if (globalHeader.length != len) {
      throw new IOException("Error reading global header.");
    }
    
    // Check byte ordering
    //0xa1b2c3d4 for us
    //0xa1b23c4d for ns
    
    boolean nativeOrdering = (byte) 0xa1 == globalHeader[0];

    //
    // Extract snaplen
    //
    
    int snaplen = 0;
    
    if (nativeOrdering) {
      for (int i = 16; i < 20; i++) {
        snaplen <<= 8;
        snaplen |= globalHeader[i] & 0xFF;
      }
    } else {
      for (int i = 19; i >= 16; i--) {
        snaplen <<= 8;
        snaplen |= globalHeader[i] & 0xFF;        
      }
    }

    byte[] recordHeader = new byte[16];
    byte[] buf = new byte[snaplen];
    
    int offset = 0;
    
    while(!eof) {
      
      //
      // Read record header
      //
      
      len = in.read(recordHeader, 0, recordHeader.length);
      
      if (recordHeader.length != len) {
        throw new IOException("Error reading record header.");        
      }
      
      //
      // Extract packet data length
      //
      
      int pktlen = 0;
      
      if (nativeOrdering) {
        for (int i = 8; i < 12; i++) {
          pktlen <<= 8;
          pktlen |= recordHeader[i] & 0xFF;
        }
      } else {
        for (int i = 11; i >= 8; i--) {
          pktlen <<= 8;
          pktlen |= recordHeader[i] & 0xFF;        
        }
      }
  
      // Read a full frame
      
      len = offset;
      
      while(len < pktlen) {
        int read = in.read(buf, offset, pktlen - offset);
    
        if (read < 0) {
          eof = true;
          break;
        }
    
        offset += read;
        len += read;
      }

      if (0 == len) {
        break;
      }
            
      //
      // Reset offset
      //
      
      offset = 0;

      byte[] keybytes = Arrays.copyOf(globalHeader, globalHeader.length + recordHeader.length);
      System.arraycopy(recordHeader, 0, keybytes, globalHeader.length, recordHeader.length);
      
      BytesWritable val = new BytesWritable(buf, pktlen);        
      BytesWritable key = new BytesWritable(keybytes);
      
      sfwriter.append(key, val);
    }
    
    in.close();

    sfwriter.close();
  }
  
  public static void main(String[] args) throws Exception {
    convert(new Configuration(), new Path(args[0]), new Path(args[1]));
  }
}
