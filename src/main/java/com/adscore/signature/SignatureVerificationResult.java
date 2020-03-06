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
 * Representation of signature verification results
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 */
public class SignatureVerificationResult {

  private String ipAddress;
  private String verdict;

  private Integer score;
  private Integer requestTime;
  private Integer signatureTime;

  private Boolean expired;

  private String error;

  public String getIpAddress() {
    return ipAddress;
  }

  void setIpAddress(String ipAddress) {
    this.ipAddress = ipAddress;
  }

  public String getVerdict() {
    return verdict;
  }

  void setVerdict(String verdict) {
    this.verdict = verdict;
  }

  public Integer getScore() {
    return score;
  }

  void setScore(Integer score) {
    this.score = score;
  }

  public Integer getRequestTime() {
    return requestTime;
  }

  void setRequestTime(Integer requestTime) {
    this.requestTime = requestTime;
  }

  public Integer getSignatureTime() {
    return signatureTime;
  }

  void setSignatureTime(Integer signatureTime) {
    this.signatureTime = signatureTime;
  }

  public Boolean getExpired() {
    return expired;
  }

  void setExpired(Boolean expired) {
    this.expired = expired;
  }

  public String getError() {
    return error;
  }

  void setError(String error) {
    this.error = error;
  }
}
