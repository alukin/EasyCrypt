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
package ua.cn.al.easycrypt;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public interface KeyWriter {

    boolean addX509CertToPKCS12(X509Certificate certificate, String pathToJKS, String alias, String jksPassword);

    byte[] serializePrivateKey(PrivateKey privateKey);

    byte[] serializePublicKey(PublicKey publicKey);

    boolean writeCertificateRequestPEM(String path, PKCS10CertificationRequest cr) throws IOException;

    boolean writePvtKeyPEM(String path, PrivateKey key) throws IOException;
    
    
    String getPvtKeyPEM(PrivateKey key) throws IOException;
    
    boolean writePvtKeyPKSC8(String path, PrivateKey key, String password)  throws IOException;
    
    boolean writePvtKeyPKCS12(String path) throws IOException;

    boolean writeX509CertificatePEM(String path, X509Certificate certificate) throws IOException;
    
    String  getX509CertificatePEM(X509Certificate certificate) throws IOException;

    String getCertificateRequestPEM(PKCS10CertificationRequest cr)  throws IOException;
    
}
