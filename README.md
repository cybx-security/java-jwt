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

### Setup factory configuration
```java
// Create the configuration to use with the factory
final ConfigurableJwtFactoryParams params = new ConfigurableJwtFactoryParams();
params.setSignature(JwtSignature.EC256);
params.setEncryption(JwtEncryption.AES_CTR);
params.setIssuer("Sample Issuer");
params.setAudience("Sample Audience");
params.setSubject("Sample Subject");
params.setNotBefore(System.currentTimeMillis());
params.setNotAfter(System.currentTimeMillis() + (1000 * 60 * 60 * 2));
params.setGenerateId(false);
```

### Creating a jwt
```java
// Access the configuration for jwt
// Create the factory with configuration
final JwtFactory factory = new JwtFactory();
factory.setParams(getJwtFactoryParams());

// Create the header claims of the token
final JwtHeaderClaims header = new JwtHeaderClaims();
header.setIssuer("something"); // overridden by factory params
header.setAudience("something"); // overridden by factory params
header.put("Custom", "abc123");

// Create the payload claims of the token
final JwtClaims payload = new JwtClaims();
payload.put("customA", 123);
payload.put("customB", "something");

// Create and sign a jwt with the factory
final Key signKey = getSuperSecretKey();
final String jwt = factory.create(header, payload, signKey);

System.out.println(jwt);
```

### Creating an encrypted jwt
```java
// Access the configuration for jwt
// Create the factory with configuration
final JwtFactory factory = new JwtFactory();
factory.setParams(getJwtFactoryParams());

// Create the header claims of the token
final JwtHeaderClaims header = new JwtHeaderClaims();
header.setIssuer("something"); // overridden by factory params
header.setAudience("something"); // overridden by factory params
header.put("Custom", "abc123");

// Create the payload claims of the token
final JwtClaims payload = new JwtClaims();
payload.put("customA", 123);
payload.put("customB", "something");

// Create and sign a jwt with the factory
final Key signKey = getSuperSecretKey();
final Key cryptKey = getSuperSecretEncryptionKey();
final String jwt = factory.create(header, payload, signKey, cryptKey);

System.out.println(jwt);
```

### Parsing and verifying a jwt
```java
// Access the encoded jwt
final String jwt = getJwt();

// Access the configuration for jwt
// Create the factory with configuration
final JwtFactory factory = new JwtFactory();
factory.setParams(getJwtFactoryParams());

// Parse the jwt encoded string
// This allows you to access claims without
// having verified them yet... please remember
// to verify them!
final UnverifiedClaims claims = factory.parse(claims);
final JwtHeaderClaims header = claims.getHeaderClaims();
final JwtClaims payload = claims.getPayloadClaims();

// Verify the claims when ready
final Key signKey = getSuperSecretKey();
factory.verify(claims, signKey);
```

### Parsing and verifying an encrypted jwt
```java
// Access the encoded jwt
final String jwt = getJwt();

// Access the configuration for jwt
// Create the factory with configuration
final JwtFactory factory = new JwtFactory();
factory.setParams(getJwtFactoryParams());

// Parse the jwt encoded string
// This allows you to access claims without
// having verified them yet... please remember
// to verify them!
final Key cryptKey = getSuperSecretEncryptionKey();
final UnverifiedClaims claims = factory.parse(claims, cryptKey);
final JwtHeaderClaims header = claims.getHeaderClaims();
final JwtClaims payload = claims.getPayloadClaims();

// Verify the claims when ready
final Key signKey = getSuperSecretKey();
factory.verify(claims, signKey);
```

## Contributors
- Tyler Suehr (tyler.suehr@cybxsecurity.com)

## License
- Apache V2
