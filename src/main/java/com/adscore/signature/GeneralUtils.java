/*
 * Copyright (c) 2020 AdScore Technologies DMCC [AE]
 *
 * Licensed under MIT License;
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.adscore.signature;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Couple of general purpose utilities created while porting from JS version of library
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
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
