package com.adscore.signature;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Couple of general purpose utilities created while porting from JS version of library
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 * @copyright AdScore Technologies DMCC [AE]
 */
class GeneralUtils {

  /** Method behaves same as js function: "str".substr(startIdx,length) */
  static String substr(String str, int startIdx, int length) {
    int endIdx = str.length();
    if (startIdx > endIdx) {
      return "";
    }

    if (startIdx + length < endIdx) {
      endIdx = startIdx + length;
    }

    return str.substring(startIdx, endIdx);
  }

  /** Method behaves same as js function: "str".substr(startIdx,length) */
  static String substr(String str, int length) {
    return substr(str, length, str.length());
  }

  /** Method behaves same as js function: "str".charAt(idx) */
  static char charAt(String str, int idx) {
    if (idx < 0 || idx >= str.length()) {
      return 0;
    }

    return str.charAt(idx);
  }

  static int characterToInt(Object obj) {
    return (int) obj;
  }

  static String encode(String key, String data) throws Exception {
    String algorithm = "HmacSHA256";
    Mac mac = Mac.getInstance(algorithm);
    mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.ISO_8859_1), algorithm));

    byte[] digest = mac.doFinal(data.getBytes());
    return new String(digest, StandardCharsets.ISO_8859_1);
  }
}
