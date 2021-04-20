# EasyCrypt, Cryptography Made Easy

Cryptograhy should be easy to use and hard to misude. Crpypography should be boring. 

EasyCrypto is Java library and utilites in Java that implements  military grade
Elliptic Curvers Cryptography (ECC) and related algorytms with extremelly simple interace. 
Programmer can just initialize library with appropriate preset and then use simpe operations to generate keys, encrypt and decrypt data.

Support of RSA based cryptography also is present for compatibility reasons.

Please see __easycrypt-examples__ sub-project for examples

___Goals of EasyCrypt design are:___

1. Provide strong cryptography swiss knife with proper parameters of all algorythms.
2. Easy of use. You do not need to know how different algorithms work inside of how to combine algorytnms in the crypto system. You choose appropriate preset an just use it.	
3. Extensibility. It should be easy to add new algorythms abd configurations.
4. It is written in Java and uses BouncyCastle library. It can be used as is in any JVM language. Java code of the library is mature and production-ready.

## Components 

* [EasyCrypt libray](easycrypt) Java library, builds to JAR file
* [EasyCrypt util](easycrypt-util) OpenSSL-like utility
* [EasyCrypt examples](easycrypt-examples) Examples of code
* [EasyCrypt identity](easycrypt-dentity) X.509 based identity library
* [EasyCrypt identity examples](easycrypt-dentity-examples) X.509 based identity library

For component description and other documentation, please see REAME.md files in the directory of the component.

## History
Previous "incarnation" of this library, called fb-crypto has antother 2 compatible libraries with very similar interface written in C++ and JavaScript/TypeSesript.
All 3 libraries have common compatibility test suite to encure full interoperability. This work was one of my open source projects at FirstBridge company.

This library contains Java code only, to be able to make quick development and may be used as upstream for former libraries.

## Copyright

EasyCrypt is free software and licensed under GPL v.2. Dual licensing is possible.

## Releases

Current release is 1.2.0. It features streamin crypto and digesting interfaces and native builds with GraalVM


### How do I get set up? ###

* Java requirements: JDK 11 or up to 16 for pure Java usage. GraalVM 21.0.0 or later for native image builds

### Experimantal stuff

The goal of experiments is to compile Java code into objects usable from other languages, particulary C++, Rust and Javascript.
There is no stable tool set yet, except GraalVM. If you know some other tools that can produce WebAssembly code from Java bytecode, please send me a note.


### GIT branches ###

* ___main___: latest stable version
* ___develop___: latest development version
* ___feature/FETURE_NAME___ - new feature development to be merged with develop branch when complete


### Contribution guidelines ###

* If you find a bug, please write issue with reproduce steps or example
* If you have patch, echancenemet or new feature, please fork this project and make cross-fork pull request to develop branch

#### Credits

Thanks to friends and colleagues.

___Andrii Zinchenko___ for great help with making the library interfaсе simple and clear.

___Serhii Lymar___ for ElGamal code and big impact on libaray improvement.


### Who do I talk to? ###

Oleksiy Lukin <alukin@gmail.com>
