package com.adscore.signature;

/**
 * Representation of signature verification results
 *
 * @author Łukasz Hyła <lhyla@iterative.pl>
 * @copyright AdScore Technologies DMCC [AE]
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
