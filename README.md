<h1>What is it?</h1>

Various Java client libraries for utilization of APIs in <a href="https://adscore.com">AdScore.com</a>

<h5> Latest version: 1.0.0 - currently available features: </h5>
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
<i>[available soon]</i>

The easiest way to utilize the library is to attach it as a Maven dependency:

```maven
<dependency>
  <groupId>com.adscore</groupId>
   <artifactId>adscore-client-libraries</artifactId>
   <version>1.0.0</version>
</dependency>
```

or as a Gradle dependency:

```gradle
compile 'com.adscore:adscore-client-libraries:1.0.0'
```

<h5>Maven/Gradle static file</h5>

Download the latest release from <a href="https://github.com/Adscore/client-libs-java/releases"> github releases<a/> and than add it as Maven depenendecy:

```maven
<dependency>
  <groupId>com.adscore</groupId>
   <artifactId>client-libraries</artifactId>
   <version>1.0.0</version>
   <scope>system</scope>
   <systemPath>${project.basedir}/libs/adscore-client-libraries-1.0.0.jar</systemPath>
</dependency>
```
or as a Gradle:

```gradle
compile files('libs/adscore-client-libraries-1.0.0.jar')
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

executing above should succesfully run unit tests and produce `client-libraries-x-x-x.jar` within `~/project-dir/build/libs` directory

If you wish you can also do:

```bash
user@PC:~/project-dir$ ./gradlew publishToMavenLocal
```

which should allow to reference library from your local repository.

<h2> Features documentation </h2>

<h3>1. SignatureVerifier</h3>

Following are few quick examples of how to use verifier, first import the entry point for library:

```java
import com.adscore.signature.SignatureVerifier;
[..]
```

than you have few options of how to verify signatures

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