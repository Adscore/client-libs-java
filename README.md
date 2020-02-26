<h1>Signature Validator</h1>
Official API

- Package version: 1.0.0

<h3>Build requirements</h3>
Java 8+
Gradle 5+


<h3>Reference requirements</h3>
Java 8+

<h3>Basic usage</h3>

Add this library as an dependency to your project

<h5> Verify with encoded key</h5>

```java
SignatureVerificationResult result = SignatureVerifier.verify(
 "signature",
 "userAgent",
 "customer",
  "encodedKey",
  true,
 "firstIpAddress",
 "secondIpAddress"
);

```

result object will contain a non-null value in verdict field in case of success
or a non-null value in error field in cases of failure

<h5>Verify with expiry</h5>

```java
SignatureVerificationResult result = SignatureVerifier.verify(
 "signature",
 "userAgent",
 "signRole",
  "decodedKey",
  12345, //expiry
 "firstIpAddress",
 "secondIpAddress"
);
```


<h5>Verify expiry with encoded key</h5>

```java
SignatureVerificationResult result = SignatureVerifier.verify(
 "signature",
 "userAgent",
 "signRole",
  "encodedKey",
  true,
  12345, //expiry
 "firstIpAddress",
 "secondIpAddress"
)
```


IF signatureTime + expiry > CurrentDateInSeconds
THEN result.getExpired() = true