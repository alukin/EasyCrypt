# EasyCrypt, Cryptography Made Easy

Cryptography should be easy to use and hard to misuse. Cryptography should be boring.

EasyCrypt is a Java library and utility written in Java that implements military-grade Elliptic-curve cryptography (ECC)
and related algorithms with an extremely simple interface. Programmers can just initialize the library with the
appropriate preset, and then use simple operations to generate keys, encrypt and decrypt data. Support of RSA-based
cryptography also is present for compatibility reasons.

Please see __easycrypt-examples__ sub-project for examples

___The Goals of EasyCrypt design are:___

1. Provide strong cryptography swiss knife with proper parameters of all algorithms.
2. Easy of use. You do not need to know how different algorithms work inside or how to combine algorithms in the
   cryptosystem. You choose the appropriate preset and just use it.
3. Extensibility. It should be easy to add new algorithms and configurations.
4. It is written in Java and uses the BouncyCastle library. It can be used as-is in any JVM language. Java code of the
   library is mature and production-ready.

## Components

* [EasyCrypt library](easycrypt) Java library, builds into a JAR file
* [EasyCrypt util](easycrypt-util) OpenSSL-like utility
* [EasyCrypt examples](easycrypt-examples) Examples of code
* [EasyCrypt identity](easycrypt-dentity) X.509 based identity library
* [EasyCrypt identity examples](easycrypt-dentity-examples) X.509 based identity library examples

For component description and other documentation, please see REAME.md files in the directory of the component.

## History

The previous "incarnation" of this library, called fb-crypto has another two compatible libraries with a very similar
interface written in C++ and JavaScript/TypeScript. All three libraries have a common compatibility test suite to ensure
full interoperability. This work was one of my open-source projects at FirstBridge company.

This library contains Java code only, to be able to make a quick development, and may be used as upstream for former
libraries.

## Copyright

EasyCrypt is free software and licensed under LGPL v.3. Dual licensing is possible, please conntact authors.

## Releases

Current release is 1.2.1. It features streaming crypto and digesting interfaces, native builds with GraalVM, 
and identity library with examples

### How do I get set up? ###

* Java requirements: JDK 11 or up to 16 for pure Java usage. GraalVM 21.0.0 or later for native image builds.

### Experimental stuff

The goal of experiments is to compile Java code into objects usable from other languages, particularly C++, Rust and
Javascript. There is no stable toolset yet, except GraalVM. If you know some other tools that can produce WebAssembly
code from Java bytecode, please send me a note.

### GIT branches ###

* ___main___ — latest stable version
* ___develop___ — latest development version
* ___feature/FEATURE_NAME___ — new feature development to be merged with the 'develop' branch when complete

### Contribution guidelines ###

* If you find a bug, please write an issue with how to reproduce steps or an example
* If you have a patch, enhancement, or new feature, please fork this project and make a cross-fork pull request to the
  'develop' branch

#### Credits

Thanks to friends and colleagues:

___Andrii Zinchenko___ for great help with making the library interfaсе simple and clear.

___Serhii Lymar___ for ElGamal code and a big impact on library improvement.

### Who do I talk to? ###

Oleksiy Lukin <alukin@gmail.com>
