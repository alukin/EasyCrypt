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
