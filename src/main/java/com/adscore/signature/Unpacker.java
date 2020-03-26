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

import java.util.HashMap;

/**
 * Copyright (c) 2020 AdScore Technologies DMCC [AE]
 *
 * @author lhyla
 */
class Unpacker {

  /**
   * Unpacks version field from the binary string
   *
   * @param signatureDecodedFromBase64 Signature already decoded from Base64
   * @return Version as as single integer.
   */
  static Integer unpackVersion(String signatureDecodedFromBase64) {
    return (Integer)
        Unpacker.unpack("Cversion", signatureDecodedFromBase64).getData().get("version");
  }

  /**
   * Unpacks data from a binary string into the respective format.
   *
   * @param format fields that have to be unpacked from data, forward slash separated.
   * @param data Binary string, already decoded from Base64
   * @return UnpackResult object which contains unpacked data as a hash map, where key is a name of
   *     the field. if result contains non-null error message then it means that unpacking failed.
   *     Data hash map is null then.
   */
  static UnpackResult unpack(String format, String data) {
    int formatPointer = 0;
    int dataPointer = 0;
    HashMap<String, Object> resultMap = new HashMap<>();
    int instruction;
    String quantifier;
    int quantifierInt;
    String label;
    String currentData;
    int i;
    int currentResult;

    while (formatPointer < format.length()) {
      instruction = SignatureVerifierUtils.charAt(format, formatPointer);
      quantifier = "";
      formatPointer++;

      while ((formatPointer < format.length())
          && SignatureVerifierUtils.isCharMatches(
              "[\\d\\*]", SignatureVerifierUtils.charAt(format, formatPointer))) {
        quantifier += SignatureVerifierUtils.charAt(format, formatPointer);
        formatPointer++;
      }
      if ("".equals(quantifier)) {
        quantifier = "1";
      }

      StringBuilder labelSb = new StringBuilder();
      while ((formatPointer < format.length()) && (format.charAt(formatPointer) != '/')) {
        labelSb.append(SignatureVerifierUtils.charAt(format, formatPointer++));
      }
      label = labelSb.toString();

      if (SignatureVerifierUtils.charAt(format, formatPointer) == '/') {
        formatPointer++;
      }

      switch (instruction) {
        case 'c':
        case 'C':
          if ("*".equals(quantifier)) {
            quantifierInt = data.length() - dataPointer;
          } else {
            quantifierInt = Integer.parseInt(quantifier, 10);
          }

          currentData = SignatureVerifierUtils.substr(data, dataPointer, quantifierInt);
          dataPointer += quantifierInt;

          for (i = 0; i < currentData.length(); i++) {
            currentResult = SignatureVerifierUtils.charAt(currentData, i);

            if ((instruction == 'c') && (currentResult >= 128)) {
              currentResult -= 256;
            }

            String key = label + (quantifierInt > 1 ? (i + 1) : "");
            resultMap.put(key, currentResult);
          }
          break;
        case 'n':
          if ("*".equals(quantifier)) {
            quantifierInt = (data.length() - dataPointer) / 2;
          } else {
            quantifierInt = Integer.parseInt(quantifier, 10);
          }

          currentData = SignatureVerifierUtils.substr(data, dataPointer, quantifierInt * 2);
          dataPointer += quantifierInt * 2;
          for (i = 0; i < currentData.length(); i += 2) {
            currentResult =
                (((SignatureVerifierUtils.charAt(currentData, i) & 0xFF) << 8)
                    + (SignatureVerifierUtils.charAt(currentData, i + 1) & 0xFF));

            String key = label + (quantifierInt > 1 ? ((i / 2) + 1) : "");
            resultMap.put(key, currentResult);
          }
          break;
        case 'N':
          if ("*".equals(quantifier)) {
            quantifierInt = (data.length() - dataPointer) / 4;
          } else {
            quantifierInt = Integer.parseInt(quantifier, 10);
          }

          currentData = SignatureVerifierUtils.substr(data, dataPointer, quantifierInt * 4);
          dataPointer += quantifierInt * 4;
          for (i = 0; i < currentData.length(); i += 4) {
            currentResult =
                (((SignatureVerifierUtils.charAt(currentData, i) & 0xFF) << 24)
                    + ((SignatureVerifierUtils.charAt(currentData, i + 1) & 0xFF) << 16)
                    + ((SignatureVerifierUtils.charAt(currentData, i + 2) & 0xFF) << 8)
                    + ((SignatureVerifierUtils.charAt(currentData, i + 3) & 0xFF)));

            String key = label + (quantifierInt > 1 ? ((i / 4) + 1) : "");
            resultMap.put(key, currentResult);
          }
          break;
        default:
          return new UnpackResult(
              String.format("Unknown format code:%s", String.valueOf(instruction)));
      }
    }

    return new UnpackResult(resultMap);
  }
}
