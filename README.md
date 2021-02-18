<h1>What is it?</h1>

Various Java client libraries for utilization of APIs in <a href="https://adscore.com">AdScore.com</a>

<h5> Latest version: 1.0.4 - currently available features: </h5>
1. SignatureVerifier

<h5> other languages: <h5>
<ul>
 <li> PHP: https://github.com/Adscore/client-libs-php </li>
 <li> JS: https://github.com/variably/adscore-node </li>
</ul>

<h3>How to use</h3>

In order to use library:
- JRE 1.8 or higher is required

<h5>Maven/Gradle central repository</h5>

The easiest way to utilize the library is to attach it as a Maven dependency:

```maven
<dependency>
  <groupId>com.adscore</groupId>
   <artifactId>adscore-client-libraries</artifactId>
   <version>1.0.4</version>
</dependency>
```

or as a Gradle dependency:

```gradle
compile 'com.adscore:adscore-client-libraries:1.0.4'
```

<h5>Maven/Gradle static file</h5>

Download the latest release from <a href="https://github.com/Adscore/client-libs-java/releases"> github releases<a/> and than add it as Maven depenendecy:

```maven
<dependency>
  <groupId>com.adscore</groupId>
   <artifactId>client-libraries</artifactId>
   <version>1.0.4</version>
   <scope>system</scope>
   <systemPath>${project.basedir}/libs/adscore-client-libraries-1.0.4.jar</systemPath>
</dependency>
```
or as a Gradle:

```gradle
compile files('libs/adscore-client-libraries-1.0.4.jar')
```

<h3>How to build library manually</h3>

If you want you can also build the library yourself. in order to do that you need to ensure:
- JDK 1.8 or higher
- Gradle 6.2.0 or higher

if above is satisfied than simply run following:

```bash
user@PC:~/project-dir$ gradle build
```
or following if you do not have gradle installed globally:
```bash
user@PC:~/project-dir$ ./gradlew build
```

executing above should succesfully run unit tests and produce `adscore-client-libraries-x-x-x.jar` within `~/project-dir/build/libs` directory

If you wish you can also do:

```bash
user@PC:~/project-dir$ ./gradlew publishToMavenLocal
```

which should allow to reference library from your local repository.

<h2> Features documentation </h2>

<h3>1. SignatureVerifier</h3>

The definition of verify function looks as follows:

```java
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
   *     THEN result is expired. If null than expiry is not checked.
   * @param isKeyBase64Encoded boolean defining if passed key is base64 encoded or not
   * @return VerificationResult
   */
  public static SignatureVerificationResult verify(
      String signature,
      String userAgent,
      String signRole,
      String key,
      [boolean isKeyBase64Encoded (=true),] // optional due existance of overloaded function
      [Integer expiry (=null),]             // optional due existance of overloaded function
      String... ipAddresses) {
```

Following are few quick examples of how to use verifier, first import the entry point for library:

```java
import com.adscore.signature.SignatureVerifier;
[..]
```

than you have at least few options of how to verify signatures:

```java

    // Verify with base64 encoded key.
    // (No expiry parameter, the default expiry time for requestTime and signatureTime is 60s)
    SignatureVerificationResult result =
        SignatureVerifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "a2V5X25vbl9iYXNlNjRfZW5jb2RlZA==",
            "73.109.57.137");

    [..]

    // Verify with checking if expired and non base64 encoded key
    //
    // IF signatureTime + expiry > CurrentDateInSeconds
    // THEN result.getExpired() = true
    result =
        SignatureVerifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
            60, // signature cant be older than 1 min 
            "73.109.57.137");
    [..]

    // Verify against number of ip4 and ip6 addresses
    //(No expiry parameter, the default expiry time for requestTime and signatureTime is 60s)
    result =
        SignatureVerifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "key_non_base64_encoded",
            false, // notify that we use non encoded key
            "73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6");
    [..]

    // Verify against number of ip4 and ip6 addresses passed as an array
    String[] ipAddresses = {"73.109.57.137", "73.109.57.138", "73.109.57.139", "73.109.57.140", "0:0:0:0:0:ffff:4d73:55d3", "0:0:0:0:0:fffff:4d73:55d4", "0:0:0:0:0:fffff:4d73:55d5", "0:0:0:0:0:fffff:4d73:55d6"};
    result =
        SignatureVerifier.verify(
            "BAYAXlNKGQFeU0oggAGBAcAAIAUdn1gbCBmA-u-kF--oUSuFw4B93piWC1Dn-D_1_6gywQAgEXCqgk2zPD6hWI1Y2rlrtV-21eIYBsms0odUEXNbRbA",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "customer",
            "a2V5X25vbl9iYXNlNjRfZW5jb2RlZA==",
            360,  // signature cant be older than 5min
            ipAddresses);
    
    
    // result object will contain a non-null value in verdict field in case of success
    // or a non-null value in error field in cases of failure
    
    if (result.getError() != null) {
      // Failed to verify signature, handle error i.e.
      Logger.warning("Failed to verify signature: " + result.getError());
    } else {
      Logger.info("Signature verification with verdict: " + result.getVerdict() + " for ip " + result.getIpAddress());
    }
);
```