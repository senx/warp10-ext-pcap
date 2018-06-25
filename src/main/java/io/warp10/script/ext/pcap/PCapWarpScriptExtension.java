package io.warp10.script.ext.pcap;

import java.util.HashMap;
import java.util.Map;

import io.warp10.warp.sdk.WarpScriptExtension;

public class PCapWarpScriptExtension extends WarpScriptExtension {
  private static final Map<String,Object> functions;
  
  static {
    functions = new HashMap<String,Object>();
    
    functions.put("PCAPPARSE", new PCAPPARSE("PCAPPARSE"));
  }
  
  @Override
  public Map<String, Object> getFunctions() {
    return functions;
  }
}
