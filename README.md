# EasyCrypt, Cryptography Made Easy 

EasyCrypto is Java library and utilites in Java that implements  military grade
Elliptic Curvers Cryptography (ECC) and related algorytms with extremelly simple interace.
Support of RSA based cryptography also is present for compatibility reasons.

___Goals of EasyCrypt design are:___

1. Provide strong cryptography swiss knife with proper parameters of all algorythms
2. Easy of use. You do not need to know how different algorithms work inside of how to combine algorytnms in the crypto system. You choose appropriate preset an just use it.	

It is written in Java and uses BouncyCastle library. It can be used as is in any JVM language. 
Java code of the library is mature and production-ready.

## Components 

* [EasyCrypt libray](cryptolib) Java library, builds to JAR file
* [EasyCrypt util](cryptoutils) OpenSSL-like utility
* [EasyCrypt examples](clyptolib-examples) Examples of code

Previous "incarnation" of this library, called fb-crypto has antother 2 compatible libraries with very similar interface written in C++ and JavaScript/TypeSec
All 3 libraries have common compatibility test suite to encure full interoperability. This work was one of my open source projects at FirstBridge company.

This library contains Java code only to be able to make quick development and may be used as upstream for former libraries.

## Copyright

EasyCrypt is free software and licensed under GPL v.2. 

## Releases

Current release is 1.0.0 amd contains Java code only.


### How do I get set up? ###

* Java requirements: JDK 11 or up to 16 for pure Java usage. GraalVM 20.0.3 or later for native image builds

### Experimantal stuff

There is no stable tool set yet, except GraalVM. Please follow links above and try latest versions of tools.
If you know some other tools that can produce WebAssembly code from Java bytecode, please send me a note.


### GIT branches ###

* ___master___: latest stable version
* ___develop___: latest development version
* ___feature/FETURE_NAME___ - new feature development to be merged with develop branch when complete
anches contain code supposed to be merget to develop branch

### Contribution guidelines ###

* If you find a bug, please write issue with reproduce steps or example
* If you have patch, echancenemet or new feature, please fork this project and make cross-fork pull request to develop branch

#### Credits

Thanks to may friends and colleagues

___Andrii Zinchenko___ for great help with making the library interfaсе simple and clear.

___Serhii Lymar___ for ElGamal code and big impact on libaray improvement.


### Who do I talk to? ###

Oleksiy Lukin <alukin@gmail.com>
