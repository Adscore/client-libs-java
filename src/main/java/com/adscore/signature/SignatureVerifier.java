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

import java.util.Date;
import java.util.HashMap;
import java.util.StringJoiner;

/**
 * Entry point of AdScore signature verification library. It expose verify method allowing to verify
 * AdScore signature against given set of ipAddress(es) for given zone.
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 */
public class SignatureVerifier {

  // constants

  private static HashMap<Integer, Field> fieldIds =
      new HashMap<Integer, Field>() {
        {
          put(0x00, new Field("requestTime", "ulong"));
          put(0x01, new Field("signatureTime", "ulong"));
          put(0x40, new Field(null, "ushort"));
          put(0x80, new Field("masterSignType", "uchar"));
          put(0x81, new Field("customerSignType", "uchar"));
          put(0xC0, new Field("masterToken", "string"));
          put(0xC1, new Field("customerToken", "string"));
          put(0xC2, new Field("masterTokenV6", "string"));
          put(0xC3, new Field("customerTokenV6", "string"));
        }
      };

  private static HashMap<String, String> results =
      new HashMap<String, String>() {
        {
          put("0", "ok");
          put("3", "junk");
          put("6", "proxy");
          put("9", "bot");
        }
      };

  // API

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature
   * @return VerificationResult
   */
  public static SignatureVerificationResult verify(
      String signature, String userAgent, String signRole, String key, String... ipAddresses) {

    return SignatureVerifier.verify(signature, userAgent, signRole, key, true, null, ipAddresses);
  }

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature
   * @param expiry number which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds
   *     THEN result is expired
   * @return VerificationResult
   */
  public static SignatureVerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      Integer expiry,
      String... ipAddresses) {

    return SignatureVerifier.verify(signature, userAgent, signRole, key, true, expiry, ipAddresses);
  }

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature
   * @param isKeyBase64Encoded boolean defining if passed key is base64 encoded or not
   * @return VerificationResult
   */
  public static SignatureVerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      boolean isKeyBase64Encoded,
      String... ipAddresses) {

    return SignatureVerifier.verify(
        signature, userAgent, signRole, key, isKeyBase64Encoded, null, ipAddresses);
  }

  /**
   * @param signature the string which we want to verify
   * @param userAgent string with full description of user agent like 'Mozilla/5.0 (Linux; Android
   *     9; SM-J530F)...'
   * @param signRole string which specifies if we operate in customer or master role. For AdScore
   *     customers this should be always set to 'customer'
   * @param key string containing related zone key
   * @param ipAddresses array of strings containing ip4 or ip6 addresses against which we check
   *     signature
   * @param expiry number which is time in seconds. IF signatureTime + expiry > CurrentDateInSeconds
   *     THEN result is expired
   * @param isKeyBase64Encoded boolean defining if passed key is base64 encoded or not
   * @return VerificationResult
   */
  public static SignatureVerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      boolean isKeyBase64Encoded,
      Integer expiry,
      String... ipAddresses) {

    key = isKeyBase64Encoded ? SignatureVerifierUtils.keyDecode(key) : key;

    SignatureVerificationResult validationResult = new SignatureVerificationResult();

    try {
      HashMap<String, Object> data;
      try {
        data = parse4(signature);
      } catch (BaseSignatureVerificationException exp) {
        if (exp instanceof SignatureRangeException) {
          data = parse3(signature);
        } else {

          validationResult.setError(exp.getMessage());
          return validationResult;
        }
      }

      String signRoleToken = (String) data.get(signRole + "Token");
      if (signRoleToken == null || signRoleToken.length() == 0) {

        validationResult.setError("sign role signature mismatch");
        return validationResult;
      }

      int signType = SignatureVerifierUtils.characterToInt(data.get(signRole + "SignType"));

      for (String ipAddress : ipAddresses) {
        String token;
        if (ipAddress == null || ipAddress.length() == 0) {
          continue;
        }
        if (IpV6Utils.validate(ipAddress)) {

          if (!data.containsKey(signRole + "TokenV6")) {
            continue;
          }
          token = (String) data.get(signRole + "TokenV6");
          ipAddress = IpV6Utils.abbreviate(ipAddress);
        } else {
          if (!data.containsKey(signRole + "Token")) {
            continue;
          }

          token = (String) data.get(signRole + "Token");
        }

        for (String result : results.keySet()) {
          switch (signType) {
            case 1:
              String signatureBase =
                  getBase(
                      result,
                      SignatureVerifierUtils.characterToInt(data.get("requestTime")),
                      SignatureVerifierUtils.characterToInt(data.get("signatureTime")),
                      ipAddress,
                      userAgent);

              boolean isHashedDataEqualToToken = hashData(signatureBase, key).equals(token);

              if (isHashedDataEqualToToken) {
                if (expiry != null
                    && SignatureVerifierUtils.characterToInt(data.get("signatureTime")) + expiry
                        < new Date().getTime() / 1000) {
                  validationResult.setExpired(true);
                  return validationResult;
                }

                validationResult.setScore(Integer.valueOf(result));
                validationResult.setVerdict(results.get(result));
                validationResult.setIpAddress(ipAddress);
                validationResult.setRequestTime(
                    Integer.parseInt(String.valueOf(data.get("requestTime"))));
                validationResult.setSignatureTime(
                    Integer.parseInt(String.valueOf(data.get("signatureTime"))));

                return validationResult;
              }
              break;
            case 2:
              validationResult.setError("unsupported signature");
              return validationResult;
            default:
              validationResult.setError("unrecognized signature");
              return validationResult;
          }
        }
      }

      validationResult.setError("no verdict");
      return validationResult;

    } catch (Exception exp) {

      validationResult.setError(exp.getMessage());
      return validationResult;
    }
  }

  // internals

  static String getBase(
      String verdict, int requestTime, int signatureTime, String ipAddress, String userAgent) {
    StringJoiner joiner = new StringJoiner("\n");

    return joiner
        .add(verdict)
        .add(String.valueOf(requestTime))
        .add(String.valueOf(signatureTime))
        .add(ipAddress)
        .add(userAgent)
        .toString();
  }

  private static HashMap<String, Object> parse3(String signature)
      throws BaseSignatureVerificationException {
    signature = SignatureVerifierUtils.fromBase64(signature);
    if (!"".equals(signature)) {
      throw new SignatureVerificationException("invalid base64 payload");
    }

    UnpackResult unpackResult =
        Unpacker.unpack(
            "Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength", signature);

    Integer version = (Integer) unpackResult.getData().get("version");

    if (version != 3) {
      throw new SignatureRangeException("unsupported version");
    }

    Long timestamp = (Long) unpackResult.getData().get("timestamp");
    if (timestamp > (new Date().getTime() / 1000)) {
      throw new SignatureVerificationException("invalid timestamp (future time)");
    }

    Integer masterTokenLength = (Integer) unpackResult.getData().get("masterTokenLength");
    String masterToken = SignatureVerifierUtils.substr(signature, 12, masterTokenLength + 12);
    unpackResult.getData().put("masterToken", masterToken);

    int s1, s2;

    if ((s1 = masterTokenLength) != (s2 = masterToken.length())) {
      throw new SignatureVerificationException(
          String.format("master token length mismatch (%s / %s)", s1, s2));
    }

    signature = SignatureVerifierUtils.substr(signature, masterTokenLength + 12);

    HashMap<String, Object> data2 =
        Unpacker.unpack("CcustomerSignType/ncustomerTokenLength", signature).getData();

    Integer customerTokenLength = (Integer) data2.get("customerTokenLength");
    String customerToken = SignatureVerifierUtils.substr(signature, 3, customerTokenLength + 3);
    data2.put("customerToken", customerToken);

    if ((s1 = customerTokenLength) != (s2 = customerToken.length())) {
      throw new SignatureVerificationException(
          String.format("customer token length mismatch (%s / %s)')", s1, s2));
    }

    unpackResult.getData().putAll(data2);

    return unpackResult.getData();
  }

  private static Field fieldTypeDef(Integer fieldId, int i) {
    if (fieldIds.get(fieldId) != null) {
      return fieldIds.get(fieldId);
    }

    String resultType = fieldIds.get(fieldId & 0xC0).getType();

    String iStr = SignatureVerifierUtils.padStart(String.valueOf(i), 2, '0');
    String resultName = resultType + iStr;

    return new Field(resultName, resultType);
  }

  private static HashMap<String, Object> parse4(String signature)
      throws BaseSignatureVerificationException {
    signature = SignatureVerifierUtils.fromBase64(signature);

    if (signature.length() == 0) {
      throw new SignatureVerificationException("invalid base64 payload");
    }

    HashMap<String, Object> data = Unpacker.unpack("Cversion/CfieldNum", signature).getData();

    int version = SignatureVerifierUtils.characterToInt(data.get("version"));
    if (version != 4) {
      throw new SignatureRangeException("unsupported version");
    }
    signature = SignatureVerifierUtils.substr(signature, 2);

    int fieldNum = SignatureVerifierUtils.characterToInt(data.get("fieldNum"));

    for (int i = 0; i < fieldNum; ++i) {
      HashMap<String, Object> header = Unpacker.unpack("CfieldId", signature).getData();

      if (header.entrySet().size() == 0 || !header.containsKey("fieldId")) {
        throw new SignatureVerificationException("premature end of signature 0x01");
      }

      Field fieldTypeDef =
          fieldTypeDef(SignatureVerifierUtils.characterToInt(header.get("fieldId")), i);
      HashMap<String, Object> v = new HashMap<>();
      HashMap<String, Object> l;

      switch (fieldTypeDef.getType()) {
        case "uchar":
          v = Unpacker.unpack("Cx/Cv", signature).getData();
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new SignatureVerificationException("premature end of signature 0x02");
          }
          signature = SignatureVerifierUtils.substr(signature, 2);
          break;
        case "ushort":
          v = Unpacker.unpack("Cx/nv", signature).getData();
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new Error("premature end of signature 0x03");
          }
          signature = SignatureVerifierUtils.substr(signature, 3);
          break;
        case "ulong":
          v = Unpacker.unpack("Cx/Nv", signature).getData();
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new Error("premature end of signature 0x04");
          }
          signature = SignatureVerifierUtils.substr(signature, 5);
          break;
        case "string":
          l = Unpacker.unpack("Cx/nl", signature).getData();
          if (!l.containsKey("l")) {
            throw new Error("premature end of signature 0x05");
          }
          if ((SignatureVerifierUtils.characterToInt(l.get("l")) & 0x8000) > 0) {
            int newl = SignatureVerifierUtils.characterToInt(l.get("l")) & 0xFF;
            l.put("l", newl);
          }

          String newV =
              SignatureVerifierUtils.substr(
                  signature, 3, SignatureVerifierUtils.characterToInt(l.get("l")));
          v.put("v", newV);
          data.put(fieldTypeDef.getName(), newV);

          if (((String) v.get("v")).length() != SignatureVerifierUtils.characterToInt(l.get("l"))) {
            throw new SignatureVerificationException("premature end of signature 0x06");
          }

          signature =
              SignatureVerifierUtils.substr(
                  signature, 3 + SignatureVerifierUtils.characterToInt(l.get("l")));

          break;
        default:
          throw new SignatureVerificationException("unsupported variable type");
      }
    }

    data.remove(String.valueOf(fieldNum));

    return data;
  }

  private static String hashData(String data, String key) throws Exception {
    return SignatureVerifierUtils.encode(key, data);
  }
}
