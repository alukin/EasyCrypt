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

package ua.cn.al.easycrypt.identity.cert;

import ua.cn.al.easycrypt.identity.utils.StringList;
import ua.cn.al.easycrypt.identity.utils.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import lombok.Getter;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.csr.CertSubject;
import ua.cn.al.easycrypt.impl.KeyWriterImpl;

/**
 * Represents X.509 certificate with Apollo-specific attributes and signed by
 * Apollo CA or self-signed
 *
 * @author alukin@gmail.com
 */
public class ExtCert extends CertBase {

    private static final Logger log = LoggerFactory.getLogger(ExtCert.class);

    @Getter
    private final X509Certificate certificate;
    private final CertAttributes cert_attr;
    private final CertAttributes issuer_attr;


    public ExtCert(X509Certificate certificate) throws CertException {
        if (certificate == null) {
            throw new CertException("Null certificate");
        }
        this.certificate = certificate;
        pubKey = certificate.getPublicKey();
        cert_attr = new CertAttributes();
        issuer_attr = new CertAttributes();
        cert_attr.setSubjectMap(CertSubject.byNamesFromPrincipal(certificate.getSubjectX500Principal()));
        issuer_attr.setSubjectMap(CertSubject.byNamesFromPrincipal(certificate.getIssuerX500Principal()));
    }

    
    
    public byte[] getActorId() {
        return cert_attr.getActorId();
    }

    public AuthorityID getAuthorityId() {
        return cert_attr.getAuthorityId();
    }


    public String getCN() {
        return cert_attr.getCn();
    }

    public String getOrganization() {
        return cert_attr.getO();
    }

    public String getOrganizationUnit() {
        return cert_attr.getOu();
    }

    public String getCountry() {
        return cert_attr.getCountry();
    }

    public String getCity() {
        return cert_attr.getCity();
    }

    public String getCertificatePurpose() {
        return "Node";
        //TODO: implement recognitioin from extended attributes
    }

    public List<String> getIPAddresses() {
        return cert_attr.IpAddresses();
    }

    public List<String> getDNSNames() {
        return null;
        //TODO: implement
    }

    public String getStateOrProvince() {
        return null;
    }

    public String getEmail() {
        return cert_attr.geteMail();
    }

    @Override
    public String toString() {
        String res = "X.509 Certificate:\n";
        res += "CN=" + cert_attr.getCn() + "\n"
            + "ApolloID=" + Hex.encode(getActorId()) + "\n";

        res += "emailAddress=" + getEmail() + "\n";
        res += "Country=" + getCountry() + " State/Province=" + getStateOrProvince()
            + " City=" + getCity();
        res += "Organization=" + getOrganization() + " Org. Unit=" + getOrganizationUnit() + "\n";
        res += "IP address=" + StringList.fromList(getIPAddresses()) + "\n";
        res += "DNS names=" + StringList.fromList(getDNSNames()) + "\n";
        return res;
    }

    public String getCertPEM() {
        KeyWriter kw = new KeyWriterImpl();
        String res="";
        try {
            res = kw.getX509CertificatePEM(certificate);
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(ExtCert.class.getName()).log(Level.SEVERE, null, ex);
        }
        return res;
    }

    /**
     * Returns whether {@code date} is within this certificate's validity period,
     * including the not-before and not-after instants. This checks dates only;
     * it does not validate signatures, trust chains, key usage, or revocation.
     */
    public boolean isValid(Date date) {
        if (date == null) {
            return false;
        }
        Date start = certificate.getNotBefore();
        Date end = certificate.getNotAfter();
        return !date.before(start) && !date.after(end);
    }

    public BigInteger getSerial() {
        return certificate.getSerialNumber();
    }

    public CertAttributes getIssuerAttrinutes() {
        return issuer_attr;
    }
    
    public CertAttributes getSubjectAttrinutes() {
        return cert_attr;
    }
    
    /**
     * Checks that the supplied certificate has the subject name named as this
     * certificate's issuer and that its public key verifies this certificate's
     * signature. This is a direct-issuer check, not full PKIX path validation.
     */
    public boolean verify(X509Certificate certificate) {
        if (certificate == null || !this.certificate.getIssuerX500Principal()
                .equals(certificate.getSubjectX500Principal())) {
            return false;
        }
        try {
            this.certificate.verify(certificate.getPublicKey());
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }
        return true;
    }
    
    /** Checks issuer/subject name equality and the certificate's self-signature. */
    public boolean isSelfSigned(){
        return isSignedBy(certificate);
    }

    /** Checks whether this certificate is directly signed by the named issuer certificate. */
    public boolean isSignedBy(X509Certificate signerCert) {
        return verify(signerCert);
    }

}
