# JSON Web Token (Java Library)

This project is a reusable library containing a hardened implementation of 
the JSON Web Token RFC 7519 for use with the Java Programming Language. Although 
this implements the protocol as specified in the RFC, there are some minor 
changes and optimizations to enhance overall security. 

These minor changes may not be compatible with all systems using jwt, but we 
think it's worth it for the security improvements! In example, this library does
not support using jwt without signatures, has updated algorithms such as HMAC
with SHA-3, and payload claims encryption using the AES algorithm.

## Prerequisites
- Java 8 JDK

## Contributors
- Tyler Suehr (tyler.suehr@cybxsecurity.com)

## License
- Apache V2