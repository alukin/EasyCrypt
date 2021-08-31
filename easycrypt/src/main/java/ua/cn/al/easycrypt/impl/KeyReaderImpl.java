/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * LICENSE
 */
package ua.cn.al.easycrypt.impl;

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.KeyReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;

import ua.cn.al.easycrypt.CryptoNotValidException;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads keys in various formats and returns in the form acceptable by EasyCrypt
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class KeyReaderImpl implements KeyReader {

    private static final Logger log = LoggerFactory.getLogger(KeyReaderImpl.class);

    @Override
    public PublicKey extractPublicKeyFromX509(X509Certificate c) throws CertificateException, CryptoNotValidException {

        PublicKey pubKey = c.getPublicKey();
        if (pubKey instanceof RSAPublicKey) {
            RSAPublicKey pk = (RSAPublicKey) pubKey;
            return pk;
        } else if (pubKey instanceof ECPublicKey) {
            // We have an EC public key, it is good
            ECPublicKey ecpk = (ECPublicKey) pubKey;
            return ecpk;
        } else {
            // Unknown key type, should never happen
            throw new CryptoNotValidException("Unknown encryption in certificate, please use ECC");
        }
    }

    @Override
    public PrivateKey readPrivateKeyPEM(InputStream input) throws IOException {
        Reader rdr = new InputStreamReader(input);
        Object obj = new PEMParser(rdr).readObject();
        PrivateKeyInfo parsed;
        if (obj instanceof PEMKeyPair) {
            PEMKeyPair kp = (PEMKeyPair) obj;
            parsed = kp.getPrivateKeyInfo();
        } else if (obj instanceof PrivateKeyInfo) {
            parsed = (PrivateKeyInfo) obj;
        } else {
            parsed = null;
        }
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey key = converter.getPrivateKey(parsed);
        return key;
    }

    @Override
    public PrivateKey readPrivateKeyPEM(InputStream input, String pvtKeyPassword) throws IOException {

        if (pvtKeyPassword == null | pvtKeyPassword.isEmpty()) {
            return readPrivateKeyPEM(input);
        }
        return readPrivateKeyPKCS8(input, pvtKeyPassword);
    }

    @Override
    public PrivateKey readPrivateKeyPKCS8(InputStream input, String password) {
        PrivateKey pk = null;
        try {
            InputStreamReader reader = new InputStreamReader(input);
            PEMParser pemParser = new PEMParser(reader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            Object object = pemParser.readObject();
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo eki = (PKCS8EncryptedPrivateKeyInfo) object;
                InputDecryptorProvider decProv = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password.toCharArray());                
                pk = converter.getPrivateKey(eki.decryptPrivateKeyInfo(decProv));
            } else if (object instanceof PEMKeyPair) {
                PEMKeyPair kp = (PEMKeyPair) object;
                PrivateKeyInfo parsed = kp.getPrivateKeyInfo();
                pk = converter.getPrivateKey(parsed);
            } else {
                log.debug("Stream does not contain PKCS#8 key");
            }
        } catch (IOException | PKCSException |OperatorCreationException ex) {
            log.error("Can not read PKCS#8 private key: {}", ex.getMessage());
            System.out.println("==="+ex.getMessage());
        } finally {
            try {
                input.close();
            } catch (IOException ex) {
            }
        }
        return pk;
    }

    @Override
    public PrivateKey readPrivateKeyPKCS12(String PKCS12filePath, String password, String keyPassword, String alias) throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyPair kp = readPKCS12File(PKCS12filePath, password, alias);
        return kp.getPrivate();
    }

    @Override
    public PublicKey readPublicKeyPKCS12(String PKCS12filePath, String password, String alias) throws KeyStoreException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyPair kp = readPKCS12File(PKCS12filePath, password, alias);
        return kp.getPublic();
    }

    @Override
    public KeyPair readPKCS12File(String path, String password, String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12", CryptoConfig.getProvider());
        FileInputStream fis = new FileInputStream(path);
        ks.load(fis, password.toCharArray());

        Enumeration aliasEnum = ks.aliases();

        Key key = null;
        Certificate cert = null;
        KeyPair kp = null;
        while (aliasEnum.hasMoreElements()) {
            String keyName = (String) aliasEnum.nextElement();
            if (keyName.compareToIgnoreCase(alias) == 0) {
                key = ks.getKey(keyName, password.toCharArray());
                cert = ks.getCertificate(keyName);
                kp = new KeyPair(cert.getPublicKey(), (PrivateKey) key);
            }
        }

        return kp;
    }

    public static X509Certificate getCertFromPKCS12File(String path, String password, String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        X509Certificate c = null;
        KeyStore p12 = KeyStore.getInstance("PKCS12", CryptoConfig.getProvider());
        p12.load(new FileInputStream(path), password.toCharArray());
        Enumeration e = p12.aliases();
        while (e.hasMoreElements()) {
            String calias = (String) e.nextElement();
            if (alias.compareTo(calias) == 0) {
                c = (X509Certificate) p12.getCertificate(alias);
                Principal subject = c.getSubjectDN();
                String[] subjectArray = subject.toString().split(",");
                for (String s : subjectArray) {
                    String[] str = s.trim().split("=");
                    String key = str[0];
                    String value = str[1];
                    log.debug("{} - {}", key, value);
                }
                break;
            }
        }
        return c;
    }

    @Override
    public X509Certificate readX509CertPEMorDER(InputStream is) {
        X509Certificate cert = null;
        try {
            CertificateFactory fact = CertificateFactory.getInstance("X.509", CryptoConfig.getProvider());
            cert = (X509Certificate) fact.generateCertificate(is);
        } catch (CertificateException ex) {
            log.error("Can not read X.509 certificate", ex);
        }
        return cert;
    }

    /**
     * Reads public key from most standard and compatible representation (ASN.1
     * in X509) Compatible with OpenSSL.
     *
     * @param keyBytes bytes of public key
     * @return re-constructed public key
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    @Override
    public PublicKey deserializePublicKey(byte[] keyBytes) throws CryptoNotValidException {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("ECDSA", CryptoConfig.getProvider());
            return kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoNotValidException("Unsupported or invalid ECC public key", ex);
        }
    }

    /**
     * Reads private key from most standard and compatible representation (ASN.1
     * in PKSC#8) Compatible with OpenSSL.
     *
     * @param keyBytes bytes of private key
     * @return re-constructed private key
     * @throws ua.cn.al.easycrypt.CryptoNotValidException
     */
    @Override
    public PrivateKey deserializePrivateKey(byte[] keyBytes) throws CryptoNotValidException {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("ECDSA", CryptoConfig.getProvider());
            return kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new CryptoNotValidException("Unsupported or invalid ECC public key", ex);
        }
    }

}
