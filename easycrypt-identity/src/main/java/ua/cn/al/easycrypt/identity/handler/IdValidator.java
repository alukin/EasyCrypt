/*
 * Copyright (C) 2021 Oleksiy Lukin 
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 */

package ua.cn.al.easycrypt.identity.handler;

import java.security.cert.X509Certificate;


/**
 * Validator of certificates signed by one of trusted signers
 * @author alukin@gmail.com
 */

public interface IdValidator {
    /**
     * Add trusted signer certificate to the internal list
     * that is used for particular certificate signature check
     * @param cert trusted certificate
     */
    void addTrustedSignerCert(X509Certificate  cert);
    /**
     * Is this certificate self-signed?
     * @param cert certificate to check
     * @return true if certificate is self-signed
     */
    boolean isSelfSigned(X509Certificate cert);
    /**
     * Is this certificate signed by one of trusted certificates?
     * @param cert certificate to check
     * @return true is this certificate is signed by one of trusted 
     */
    boolean isTrusted(X509Certificate cert);
    /**
     * Verify signed data with public certificate. IUt proves that other side has
     * valid private key and can sign
     * @param certificate Crtificate of other side
     * @param data data being signed
     * @param signature signature of the data
     * @return true if signature is OK
     */
    public boolean verifySignedData(X509Certificate certificate, byte[] data, byte[] signature);
   
}
