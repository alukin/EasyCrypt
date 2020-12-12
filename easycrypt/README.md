## EasyCrypt Java lirbary

Java crypto library designed for simplicity bu with military-grade cryptography inside.

## Compilation

You need JDK 11 or later and Maven 3.6.0 or later
Simple command will do the job
<pre>
mvn clean install
</pre>

### Notes on ECC curves support

This citation from https://java.com/en/configure_crypto.html#DisableWeakNamedCurves :

Disable weak named curves by default in TLS, CertPath, and Signed JARs
The following named elliptic curves will be disabled by default in TLS, CertPath, and Signed JARs:

secp112r1, secp112r2, secp128r1, secp128r2, secp160k1, secp160r1, secp160r2, secp192k1,
secp192r1, secp224k1, secp224r1, secp256k1, sect113r1, sect113r2, sect131r1, sect131r2,
sect163k1, sect163r1, sect163r2, sect193r1, sect193r2, sect233k1, sect233r1, sect239k1,
sect283k1, sect283r1, sect409k1, sect409r1, sect571k1, sect571r1, X9.62 c2tnb191v1,
X9.62 c2tnb191v2, X9.62 c2tnb191v3, X9.62 c2tnb239v1, X9.62 c2tnb239v2, X9.62 c2tnb239v3,
X9.62 c2tnb359v1, X9.62 c2tnb431r1, X9.62 prime192v2, X9.62 prime192v3, X9.62 prime239v1,
X9.62 prime239v2, X9.62 prime239v3, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1
These are rarely used curves that are deprecated or have not been implemented using modern cryptographic techniques. Any elliptic curve algorithm or certificate used in CertPath, TLS or signed JARs that uses one of these curves will be restricted by default.

Note that for TLS, this action goes a step further than the previously released restriction for TLS on the cryptographic roadmap: "Disabled non-NIST Suite B EC curves (sect283k1, sect283r1, sect409k1, sect409r1, sect571k1, sect571r1, secp256k1) when negotiating TLS sessions". In particular, this will restrict more curves and also restrict them even if they are explicitly included in the jdk.tls.namedGroups system property.

Curves that will remain enabled are: secp256r1, secp384r1, secp521r1, X25519, and X448.

We will provide a mechanism for re-enabling these curves if necessary when the change is released.



### Who do I talk to? ###

Oleksiy Lukin <alukin@gmail.com>
