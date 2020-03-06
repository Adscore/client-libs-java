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

import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddressString;

/**
 * Utils for handling ipV6
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 */
class IpV6Utils {

  /**
   * @param ipAddress string which will be checked if contains correct ip6 address
   * @return true if ipAddress is ip6, false otherwise
   */
  static boolean validate(String ipAddress) {
    return new IPAddressString(ipAddress).isIPv6();
  }

  /**
   * @param ipAddress string with address which we want to abbreviate
   * @return RFC1924 ip6 https://tools.ietf.org/html/rfc1924
   * @throws SignatureVerificationException
   */
  static String abbreviate(String ipAddress) throws SignatureVerificationException {
    IPAddressString ip6 = new IPAddressString(ipAddress);

    if (!ip6.isIPv6()) {
      throw new SignatureVerificationException(String.format("Invalid address: %s", ipAddress));
    }

    try {
      return new IPAddressString(ipAddress).toAddress().toIPv6().toBase85String();
    } catch (AddressStringException e) {
      throw new SignatureVerificationException(String.format("Invalid address: %s", ipAddress));
    }
  }
}
