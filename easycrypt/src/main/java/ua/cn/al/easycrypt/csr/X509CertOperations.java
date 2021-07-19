/*
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

package ua.cn.al.easycrypt.csr;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 *
 * @author alukin@gmail.com
 */
public interface X509CertOperations {

    X509Certificate createSelfSignedX509v3(KeyPair kp, CertificateRequestData certData) throws IOException;
    
    X509Certificate createSelfSignedX509v3(KeyPair kp, CertificateRequestData certData, Date validityBegin, Date validityEnd) throws IOException;

    PKCS10CertificationRequest createX509CertificateRequest(KeyPair kp, CertificateRequestData certData, boolean allowCertSign, String challengePassword) throws IOException;

    public X509Certificate signCert(PKCS10CertificationRequest req, X509Certificate caCert, PrivateKey caKey, Date validityBegin, Date validityEnd);
    
}
