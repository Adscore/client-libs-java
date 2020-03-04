package com.adscore.signature;

import com.adscore.signature.ex.BaseSignatureVerificationException;
import com.adscore.signature.ex.SignatureRangeException;
import com.adscore.signature.ex.SignatureVerificationException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.StringJoiner;
import java.util.regex.Pattern;

/**
 * Entry point of AdScore signature verification library. It expose verify method allowing to verify
 * AdScore signature against given set of ipAddress(es) for given zone.
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 * @copyright AdScore Technologies DMCC [AE]
 */
public class SignatureVerifier {

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

    return SignatureVerifier.verify(signature, userAgent, signRole, key, false, null, ipAddresses);
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

    return SignatureVerifier.verify(
        signature, userAgent, signRole, key, false, expiry, ipAddresses);
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

    key = isKeyBase64Encoded ? keyDecode(key) : key;

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

      int signType = GeneralUtils.characterToInt(data.get(signRole + "SignType"));

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
        HashMap<String, String> results = new HashMap<>();

        results.put("0", "ok");
        results.put("3", "junk");
        results.put("6", "proxy");
        results.put("9", "bot");

        for (String result : results.keySet()) {
          switch (signType) {
            case 1:
              String signatureBase =
                  getBase(
                      result,
                      GeneralUtils.characterToInt(data.get("requestTime")),
                      GeneralUtils.characterToInt(data.get("signatureTime")),
                      ipAddress,
                      userAgent);

              boolean isHashedDataEqualToToken = hashData(signatureBase, key).equals(token);

              if (isHashedDataEqualToToken) {
                if (expiry != null
                    && GeneralUtils.characterToInt(data.get("signatureTime")) + expiry
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

  /**
   * @param key in base64 format
   * @return decoded key
   */
  static String keyDecode(String key) {
    return SignatureVerifier.atob(key);
  }

  static String atob(String str) {
    return new String(Base64.getMimeDecoder().decode(str.getBytes()), StandardCharsets.ISO_8859_1);
  }

  static String padStart(String inputString, int length, char c) {
    if (inputString.length() >= length) {
      return inputString;
    }
    StringBuilder sb = new StringBuilder();
    while (sb.length() < length - inputString.length()) {
      sb.append(c);
    }
    sb.append(inputString);

    return sb.toString();
  }

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

  private static String fromBase64(String data) {
    return atob(data.replace('_', '/').replace('-', '+'));
  }

  private static HashMap<String, Object> unpack(String format, String data)
      throws SignatureVerificationException {
    int formatPointer = 0;
    int dataPointer = 0;
    HashMap<String, Object> result = new HashMap<>();
    int instruction;
    String quantifier;
    int quantifierInt;
    String label;
    String currentData;
    int i;
    int currentResult;

    while (formatPointer < format.length()) {
      instruction = GeneralUtils.charAt(format, formatPointer);
      quantifier = "";
      formatPointer++;

      while ((formatPointer < format.length())
          && isCharMatches("[\\d\\*]", GeneralUtils.charAt(format, formatPointer))) {
        quantifier += GeneralUtils.charAt(format, formatPointer);
        formatPointer++;
      }
      if ("".equals(quantifier)) {
        quantifier = "1";
      }

      StringBuilder labelSb = new StringBuilder();
      while ((formatPointer < format.length()) && (format.charAt(formatPointer) != '/')) {
        labelSb.append(GeneralUtils.charAt(format, formatPointer++));
      }
      label = labelSb.toString();

      if (GeneralUtils.charAt(format, formatPointer) == '/') {
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

          currentData = GeneralUtils.substr(data, dataPointer, quantifierInt);
          dataPointer += quantifierInt;

          for (i = 0; i < currentData.length(); i++) {
            currentResult = GeneralUtils.charAt(currentData, i);

            if ((instruction == 'c') && (currentResult >= 128)) {
              currentResult -= 256;
            }

            String key = label + (quantifierInt > 1 ? (i + 1) : "");
            result.put(key, currentResult);
          }
          break;
        case 'n':
          if ("*".equals(quantifier)) {
            quantifierInt = (data.length() - dataPointer) / 2;
          } else {
            quantifierInt = Integer.parseInt(quantifier, 10);
          }

          currentData = GeneralUtils.substr(data, dataPointer, quantifierInt * 2);
          dataPointer += quantifierInt * 2;
          for (i = 0; i < currentData.length(); i += 2) {
            currentResult =
                (((GeneralUtils.charAt(currentData, i) & 0xFF) << 8)
                    + (GeneralUtils.charAt(currentData, i + 1) & 0xFF));

            String key = label + (quantifierInt > 1 ? ((i / 2) + 1) : "");
            result.put(key, currentResult);
          }
          break;
        case 'N':
          if ("*".equals(quantifier)) {
            quantifierInt = (data.length() - dataPointer) / 4;
          } else {
            quantifierInt = Integer.parseInt(quantifier, 10);
          }

          currentData = GeneralUtils.substr(data, dataPointer, quantifierInt * 4);
          dataPointer += quantifierInt * 4;
          for (i = 0; i < currentData.length(); i += 4) {
            currentResult =
                (((GeneralUtils.charAt(currentData, i) & 0xFF) << 24)
                    + ((GeneralUtils.charAt(currentData, i + 1) & 0xFF) << 16)
                    + ((GeneralUtils.charAt(currentData, i + 2) & 0xFF) << 8)
                    + ((GeneralUtils.charAt(currentData, i + 3) & 0xFF)));

            String key = label + (quantifierInt > 1 ? ((i / 4) + 1) : "");
            result.put(key, currentResult);
          }
          break;
        default:
          throw new SignatureVerificationException(
              String.format("Unknown format code:%s", String.valueOf(instruction)));
      }
    }

    return result;
  }

  private static boolean isCharMatches(String regex, int formatChar) {
    return Pattern.compile(regex).matcher(String.valueOf(formatChar)).matches();
  }

  private static HashMap<String, Object> parse3(String signature)
      throws BaseSignatureVerificationException {
    signature = fromBase64(signature);
    if (!"".equals(signature)) {
      throw new SignatureVerificationException("invalid base64 payload");
    }

    HashMap<String, Object> data1 =
        unpack(
            "Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength", signature);

    Integer version = (Integer) data1.get("version");

    if (version != 3) {
      throw new SignatureRangeException("unsupported version");
    }

    Long timestamp = (Long) data1.get("timestamp");
    if (timestamp > (new Date().getTime() / 1000)) {
      throw new SignatureVerificationException("invalid timestamp (future time)");
    }

    Integer masterTokenLength = (Integer) data1.get("masterTokenLength");
    String masterToken = GeneralUtils.substr(signature, 12, masterTokenLength + 12);
    data1.put("masterToken", masterToken);

    int s1, s2;

    if ((s1 = masterTokenLength) != (s2 = masterToken.length())) {
      throw new SignatureVerificationException(
          String.format("master token length mismatch (%s / %s)", s1, s2));
    }

    signature = GeneralUtils.substr(signature, masterTokenLength + 12);

    HashMap<String, Object> data2 = unpack("CcustomerSignType/ncustomerTokenLength", signature);

    Integer customerTokenLength = (Integer) data2.get("customerTokenLength");
    String customerToken = GeneralUtils.substr(signature, 3, customerTokenLength + 3);
    data2.put("customerToken", customerToken);

    if ((s1 = customerTokenLength) != (s2 = customerToken.length())) {
      throw new SignatureVerificationException(
          String.format("customer token length mismatch (%s / %s)')", s1, s2));
    }

    data1.putAll(data2);

    return data1;
  }

  private static Field fieldTypeDef(Integer fieldId, int i) {
    HashMap<Integer, Field> fieldIds = new HashMap<>();

    fieldIds.put(0x00, new Field("requestTime", "ulong"));
    fieldIds.put(0x01, new Field("signatureTime", "ulong"));
    fieldIds.put(0x40, new Field(null, "ushort"));
    fieldIds.put(0x80, new Field("masterSignType", "uchar"));
    fieldIds.put(0x81, new Field("customerSignType", "uchar"));
    fieldIds.put(0xC0, new Field("masterToken", "string"));
    fieldIds.put(0xC1, new Field("customerToken", "string"));
    fieldIds.put(0xC2, new Field("masterTokenV6", "string"));
    fieldIds.put(0xC3, new Field("customerTokenV6", "string"));

    if (fieldIds.get(fieldId) != null) {
      return fieldIds.get(fieldId);
    }

    String resultType = fieldIds.get(fieldId & 0xC0).getType();

    String iStr = padStart(String.valueOf(i), 2, '0');
    String resultName = resultType + iStr;

    return new Field(resultName, resultType);
  }

  private static HashMap<String, Object> parse4(String signature)
      throws BaseSignatureVerificationException {
    signature = fromBase64(signature);

    if (signature.length() == 0) {
      throw new SignatureVerificationException("invalid base64 payload");
    }

    HashMap<String, Object> data = unpack("Cversion/CfieldNum", signature);

    int version = GeneralUtils.characterToInt(data.get("version"));
    if (version != 4) {
      throw new SignatureRangeException("unsupported version");
    }
    signature = GeneralUtils.substr(signature, 2);

    int fieldNum = GeneralUtils.characterToInt(data.get("fieldNum"));

    for (int i = 0; i < fieldNum; ++i) {
      HashMap<String, Object> header = unpack("CfieldId", signature);

      if (header.entrySet().size() == 0 || !header.containsKey("fieldId")) {
        throw new SignatureVerificationException("premature end of signature 0x01");
      }

      Field fieldTypeDef = fieldTypeDef(GeneralUtils.characterToInt(header.get("fieldId")), i);
      HashMap<String, Object> v = new HashMap<>();
      HashMap<String, Object> l;

      switch (fieldTypeDef.getType()) {
        case "uchar":
          v = unpack("Cx/Cv", signature);
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new SignatureVerificationException("premature end of signature 0x02");
          }
          signature = GeneralUtils.substr(signature, 2);
          break;
        case "ushort":
          v = unpack("Cx/nv", signature);
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new Error("premature end of signature 0x03");
          }
          signature = GeneralUtils.substr(signature, 3);
          break;
        case "ulong":
          v = unpack("Cx/Nv", signature);
          if (v.containsKey("v")) {
            data.put(fieldTypeDef.getName(), v.get("v"));
          } else {
            throw new Error("premature end of signature 0x04");
          }
          signature = GeneralUtils.substr(signature, 5);
          break;
        case "string":
          l = unpack("Cx/nl", signature);
          if (!l.containsKey("l")) {
            throw new Error("premature end of signature 0x05");
          }
          if ((GeneralUtils.characterToInt(l.get("l")) & 0x8000) > 0) {
            int newl = GeneralUtils.characterToInt(l.get("l")) & 0xFF;
            l.put("l", newl);
          }

          String newV = GeneralUtils.substr(signature, 3, GeneralUtils.characterToInt(l.get("l")));
          v.put("v", newV);
          data.put(fieldTypeDef.getName(), newV);

          if (((String) v.get("v")).length() != GeneralUtils.characterToInt(l.get("l"))) {
            throw new SignatureVerificationException("premature end of signature 0x06");
          }

          signature = GeneralUtils.substr(signature, 3 + GeneralUtils.characterToInt(l.get("l")));

          break;
        default:
          throw new SignatureVerificationException("unsupported variable type");
      }
    }

    data.remove(String.valueOf(fieldNum));

    return data;
  }

  private static String hashData(String data, String key) throws Exception {
    return GeneralUtils.encode(key, data);
  }
}
