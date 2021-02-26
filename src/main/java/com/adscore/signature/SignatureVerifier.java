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

/**
 * Entry point of AdScore signature verification library. It expose verify method allowing to verify
 * AdScore signature against given set of ipAddress(es) for given zone.
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 */
public class SignatureVerifier {

  public static final int DEFAULT_EXPIRY_TIME_SEC = 60;

  /**
   * Default request and signature expiration is set to 60s
   *
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
    return SignatureVerifier.verify(
        signature, userAgent, signRole, key, true, DEFAULT_EXPIRY_TIME_SEC, ipAddresses);
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
   * Default request and signature expiration is set to 60s
   *
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
        signature,
        userAgent,
        signRole,
        key,
        isKeyBase64Encoded,
        DEFAULT_EXPIRY_TIME_SEC,
        ipAddresses);
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

    return new SignatureVerifierService()
        .verifySignature(
            signature, userAgent, signRole, key, isKeyBase64Encoded, expiry, ipAddresses);
  }
}
