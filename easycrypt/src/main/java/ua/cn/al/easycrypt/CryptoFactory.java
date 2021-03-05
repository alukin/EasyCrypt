/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

package ua.cn.al.easycrypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import lombok.extern.slf4j.Slf4j;
import ua.cn.al.easycrypt.csr.X509CertOperations;
import ua.cn.al.easycrypt.impl.ecc.KeyGeneratorEC;
import ua.cn.al.easycrypt.impl.rsa.KeyGeneratorRSA;
import ua.cn.al.easycrypt.impl.CryptoSignatureImpl;
import ua.cn.al.easycrypt.impl.ecc.AsymJCEECDHImpl;
import ua.cn.al.easycrypt.impl.ecc.ElGamalCryptoImpl;
import ua.cn.al.easycrypt.impl.ecc.AsymJCEIESImpl;
import ua.cn.al.easycrypt.impl.JCEDigestImpl;
import ua.cn.al.easycrypt.impl.KeyReaderImpl;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;
import ua.cn.al.easycrypt.impl.csr.X509CertOperationsImpl;
import ua.cn.al.easycrypt.impl.ecc.SymJCEImpl;
import ua.cn.al.easycrypt.impl.rsa.AsymCryptorRSAImpl;

/**
 * Factory that creates configured implementations of Crypto interfaces. These
 * all crypto routines that could be used with any supported encryption system
 * defined in CryptoParams,
 *
 * @author alukin@gmail.com
 */
@Slf4j
public class CryptoFactory {

    private final CryptoParams params;

    private CryptoFactory(CryptoParams p) {
        params = p;
    }

    /**
     * Creates instance of factory with parameters
     *
     * @param p set of crypto parameters, @see CryptoParams
     * @return ready to use factory with defined parameter set
     */
    public static CryptoFactory newInstance(CryptoParams p) {
        return new CryptoFactory(p);
    }

    /**
     * Creates default factory instance that uses CryptoParams.createDefault() to set crypto parameters
     *
     * @return CryptoFactory with default parameter set and algorithms (strongest)
     */
    public static CryptoFactory newInstance() {
        return new CryptoFactory(CryptoConfig.createDefaultParams());
    }

    /**
     * Instantiates symmetrical crypto routines with agreed parameters
     *
     * @return symmetrical crypto routines instance
     */
    public SymCryptor getSymCryptor() {
        return new SymJCEImpl(params);
    }

    /**
     * Instantiates routines for data encryption data using Elliptic Curves
     * Diffie-Hellman key agreement and agreed AES-128 or AES-256 encryption. It
     * is possible to use one-step ECDH using pre-defined keys or 2-step ECDHE
     * on Ephemeral keys. Ephemeral means that key pairs are created from random
     * seed on the fly, common key produced from them and then keys being thrown
     * away. This is most secure scheme but requires 2 step of key exchange
     *
     * @return instance of crypto routines with agreed parameters
     *
     */
    public AsymCryptorDH getAsymCryptorDH() {
        return new AsymJCEECDHImpl(params);
    }

    /**
     * Creates instance of crypto routines for Integrated Encryption Scheme.
     * Some default ECC IES (see Boucny Caslte library) is used for ECC
     * cryptography. With ECC size of message is not limited. In case of RSA
     * cryptography default RSA encryption scheme is used. Note, that size of
     * message is very limited in that case.
     *
     * @return
     */
    public AsymCryptor getAsymCryptor() throws CryptoNotValidException {
        if ("EC".equals(params.signatureSchema)) {
            return new AsymJCEIESImpl(params);
        } else {
            return new AsymCryptorRSAImpl(params);
        }
    }
    
    /**
     * Creates instance of signer and signature verificator for defined
     * encryption scheme
     *
     * @return signer/verifier instance
     */
    public CryptoSignature getCryptoSiganture() {
        return new CryptoSignatureImpl(params);
    }


    /**
     * Creates instance of ElGammal procedures
     *
     * @return ElGammal procedures instance
     */
    public ElGamalCrypto getElGamalCrypto() {
        return new ElGamalCryptoImpl(params);
    }

    /**
     * Creates instance of various digesters. Default digester could be
     * different for different values of CryptoParans. It is optimized by
     * security and performance. But anyway any implemented digester is
     * available.
     *
     * @return
     */
    public Digester getDigesters() {
        return new JCEDigestImpl(params);
    }

    /**
     * Creates key reader instance, able to read keys in different formats.
     * Usually, key reader does not depend on encryption Schema
     *
     * @return Key reader instance
     */
    public KeyReader getKeyReader() {
        return new KeyReaderImpl();
    }

    /**
     * Creates key write instance, able to write keys in different formats.
     * Usually, key rwriter does not depend on encryption Schema
     *
     * @return Key reader instance
     */
    public KeyWriter getKeyWriter() {
        return new KeyWriterImpl();
    }

    /**
     * Creates instance of key generator.
     *
     * @return Key generator for chosen crypto scheme
     */
    public KeyGenerator getKeyGenerator() {
        if ("EC".equals(params.signatureSchema)) {
            return new KeyGeneratorEC(params);
        } else {
            //RSA
            return new KeyGeneratorRSA(params);
        }
    }

    public X509CertOperations getX509CertOperations(){
        return new X509CertOperationsImpl(params);
    } 
    
    /**
     * Crypto parameters that are in use of current CryptoFactory instance
     * @return Crypto parameters that are in use 
     */
    public CryptoParams getCryptoParams() {
        return params;
    }

    public DigestOutputStream getDigestOutputStream(OutputStream sink) {
        MessageDigest digest=null;
        try {
            digest = MessageDigest.getInstance(params.digester);
        } catch (NoSuchAlgorithmException ex) {
            log.error("Can not create digester for {}",params.digester, ex);
        }
        return new DigestOutputStream(sink, digest);
    }

    public CipherOutputStream getCipherOutputStream(OutputStream sink, byte[] IV, byte[] key) throws CryptoNotValidException {
        SymCryptor sc = getSymCryptor();
        sc.setIV(IV);
        sc.setKey(key);
        Cipher c=null;
        try {
            c = sc.getCipher(Cipher.ENCRYPT_MODE);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoFactory.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CryptoFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new CipherOutputStream(sink, c);
    }

    public CipherInputStream getCipherInputStream(InputStream source ,byte[] IV, byte[] key ) throws CryptoNotValidException {
        SymCryptor sc = getSymCryptor();
        sc.setIV(IV);
        sc.setKey(key);
        Cipher c=null;
        try {
            c = sc.getCipher(Cipher.DECRYPT_MODE);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CryptoFactory.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(CryptoFactory.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new CipherInputStream(source,c);
    }
}
