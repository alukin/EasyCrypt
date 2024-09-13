/*
 * Copyright (C) 2018-2024 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ua.cn.al.easycrypt;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Reads keys in various formats and returns in the form acceptable by EasyCrypt
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface KeyReader {

    /**
     * Reads X.509 certificate from input stream in PEM or DER format
     *
     * @param is Input stream from file or other source
     * @return PArsed X.509 certificate or null if stream is in uknown format or
     * not readable
     */
    X509Certificate readX509CertPEMorDER(InputStream is);

    /**
     * Gets certificate owner's public key from parsed X.509 certificate
     *
     * @param c certificate containing user's public key
     * @return public key ready to use in crypto routines
     * @throws CertificateException
     * @throws CryptoNotValidException
     */
    PublicKey extractPublicKeyFromX509(X509Certificate c) throws CertificateException, CryptoNotValidException;

    /**
     * Reads unprotected private key from PEM file
     *
     * @param input stream containing PEM file
     * @return private key or null if stream is not readable or could not be
     * parsed
     * @throws IOException
     */
    PrivateKey readPrivateKeyPEM(InputStream input) throws IOException;

    /**
     * Reads private key from password-protected PEM stream
     *
     * @param input input stream that contains private key
     * @param pvtKeyPassword if password is set, method assumes PKCS#8 file. If
     * it is null or empty, it is just entry for readPrivateKeyPEM(InputStream
     * input) method
     * @return private key or null if key can not be extracted
     * @throws IOException
     */
    PrivateKey readPrivateKeyPEM(InputStream input, String pvtKeyPassword) throws IOException;

    /**
     * Reads private key from password-protected PEM stream
     *
     * @param input input stream that contains private key
     * @param pvtKeyPassword if password is set, method assumes PKCS#8 file. If
     * it is null or empty, it is just entry for readPrivateKeyPEM(InputStream
     * input) method
     * @return private key or null if key can not be extracted
     * @throws IOException
     */
    PrivateKey readPrivateKeyPKCS8(InputStream input, String pvtKeyPassword) throws IOException;

    /**
     * Reads public and private key pair from PKCS#12 key store
     *
     * @param path path to key store file
     * @param password password to keystore
     * @param alias alias of keypair in keystore
     * @return key pair ready to use in crypto routines
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    KeyPair readPKCS12File(String path, String password, String alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException;

    /**
     * Reads private key from PKCS#12 file
     *
     * @param PKCS12filePath path to key store file
     * @param password password to key store
     * @param keyPassword password to private key
     * @param alias alias of private key or key pair in the key store
     * @return private key or null if something goes wrong
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    PrivateKey readPrivateKeyPKCS12(String PKCS12filePath, String password, String keyPassword, String alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException;

    /**
     * Reads public key fro key store
     * @param PKCS12filePath path to keystore file
     * @param password password to key store
     * @param alias alias of key in the key store
     * @return public key of null if something goes wrong
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    PublicKey readPublicKeyPKCS12(String PKCS12filePath, String password, String alias) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException;

    /**
     * Reads private key from most standard and compatible representation (ASN.1
     * in PKSC#8) Compatible with OpenSSL.
     *
     * @param keyBytes bytes of private key
     * @return re-constructed private key
     * @throws CryptoNotValidException
     */
    PrivateKey deserializePrivateKey(byte[] keyBytes) throws CryptoNotValidException;

    /**
     * Reads public key from most standard and compatible representation (ASN.1
     * in X509) Compatible with OpenSSL.
     *
     * @param keyBytes bytes of public key
     * @return re-constructed public key
     * @throws CryptoNotValidException
     */
    PublicKey deserializePublicKey(byte[] keyBytes) throws CryptoNotValidException;
}
