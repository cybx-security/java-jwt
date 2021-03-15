# JSON Web Token (Java Library)

A reusable library containing a hardened implementation of the JSON Web 
Token RFC 7519 for use with the Java Programming Language. Although this 
implements the protocol as specified in the RFC, there are some minor changes 
and optimizations to enhance overall security. 

Security-improved changes may not be compatible with all systems using jwt. 
In example, this library does not support using jwt without signatures, has 
updated algorithms such as HMAC with SHA-3, and payload claims encryption 
using the AES algorithm.

## Prerequisites
- Java 8 JDK

## Usage Examples

### Add to `pom.xml`
```xml
<dependency>
    <groupId>com.cybxsecurity</groupId>
    <artifactId>jwt</artifactId>
    <version>2.0.0</version>
</dependency>
```

### Creating a signed jwt:
```java
final Jwt jwt = new Jwt();
jwt.setParameters(myCustomParamsInstance);
jwt.getPayloadClaims().put("a", "abc");
jwt.getPayloadClaims().put("b", 123);

final String token = jwt.compact(mySignKey);
// do something with jwt token
```

### Creating an encrypted signed jwt:
```java
final Jwt jwt = new Jwt();
jwt.setParameters(myCustomParamsInstance);
jwt.getPayloadClaims().put("a", "abc");
jwt.getPayloadClaims().put("b", 123);

final String token = jwt.compact(mySignKey, myEncryptKey);
// do something with encrypted jwt token
```

### Parsing and verifying a jwt:
```java
final Jwt jwt = new Jwt();
jwt.setParameters(myCustomParamsInstance);
jwt.parse(jwtStr);
jwt.verify(mySignKey);
```

### Parsing, decrypting, and verifying a jwt:
```java
final Jwt jwt = new Jwt();
jwt.setParameters(myCustomParamsInstance);
jwt.parse(jwtStr);
jwt.decrypt(myDecryptKey);
jwt.verify(mySignKey);
```

## Contributors
- Tyler Suehr (tyler.suehr@cybxsecurity.com)

## License
- Apache V2
