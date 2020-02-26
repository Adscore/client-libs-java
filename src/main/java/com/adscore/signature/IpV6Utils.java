package com.adscore.signature;

import com.adscore.signature.ex.SignatureVerificationException;
import inet.ipaddr.AddressStringException;
import inet.ipaddr.IPAddressString;

/**
 * Utils for handling ipV6
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 * @copyright AdScore Technologies DMCC [AE]
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
