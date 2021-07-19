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

package ua.cn.al.easycrypt.identity.cert;

import ua.cn.al.easycrypt.identity.utils.StringList;
import ua.cn.al.easycrypt.identity.utils.Hex;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.IPAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Properties;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.KeyGenerator;
import ua.cn.al.easycrypt.KeyWriter;
import ua.cn.al.easycrypt.csr.CertificateRequestData;
import ua.cn.al.easycrypt.csr.CertificateRequestData.CSRType;
import ua.cn.al.easycrypt.csr.X509CertOperations;


/**
 * Certificate signing request with additional identity-specific attributes
 *
 * @author alukin@gmail.com
 */
public class ExtCSR extends CertBase {

    private static final Logger log = LoggerFactory.getLogger(ExtCSR.class);
    private CertificateRequestData csrData;
    private String challengePassword = "";
    private byte[] actorID;
    private AuthorityID authorityID;
    private final KeyWriter kw;
    private PrivateKey pvtKey;
    
    public ExtCSR() {
        actorID = new BigInteger(ACTOR_ID_LENGTH, new SecureRandom()).toByteArray();
        authorityID = new AuthorityID();
        kw = factory.getKeyWriter();
        csrData = new CertificateRequestData(CertificateRequestData.CSRType.HOST);
    }
    
    public static ExtCSR fromProperties(Properties prop, CSRType aType){
        ExtCSR res = new ExtCSR();
        res.csrData = CertificateRequestData.fromProperty(prop, aType);
        return res;
    }

    public static ExtCSR fromPKCS10(PKCS10CertificationRequest cr, PrivateKey prvt) {
        ExtCSR res = new ExtCSR();
        try {
            CertAttributes va  = new CertAttributes();
            va.setSubject(cr.getSubject());
            va.setAttributes(cr.getAttributes());
            res.setCN(va.getCn());
            res.setAuthorityId(va.getAuthorityId());
            res.setActorId(va.getActorId());
            res.setCountry(va.getCountry());
            res.setState(va.getState());
            res.setCity(va.getCity());
            res.setOrg(va.getO());
            res.setOrgUnit(va.getOu());

            SubjectPublicKeyInfo pkInfo = cr.getSubjectPublicKeyInfo();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            res.pubKey = converter.getPublicKey(pkInfo);
            res.pvtKey=prvt;  
        } catch (CertException | IOException ex) {
            log.error("Error reading public key frpm PKSC#10", ex);
        }
        return res;
    }

    public static ExtCSR fromCertificate(ExtCert cert, PrivateKey prvt) {
        ExtCSR res = new ExtCSR();
        res.setAuthorityId(cert.getAuthorityId().getAuthorityID());
        byte[] vid = cert.getActorId();
        if (vid == null) {
            vid = new BigInteger(128, new SecureRandom()).toByteArray();
        }
        res.setActorId(vid);
        res.setCN(cert.getCN());
        res.setEmail(cert.getEmail());
        res.setOrg(cert.getOrganization());
        res.setOrgUnit(cert.getOrganizationUnit());
        res.setCountry(cert.getCountry());
        res.setState(cert.getStateOrProvince());
        res.setCity(cert.getCity());
        res.setIP(StringList.fromList(cert.getIPAddresses()));
        res.setDNSNames(StringList.fromList(cert.getDNSNames()));
        res.pubKey = cert.getPublicKey();
        res.pvtKey = prvt;
        return res;
    }

    public static boolean isValidIPAddresList(String ipList) {
        boolean res = true;
        String[] addr = ipList.split(",");
        for (String a : addr) {
            res = IPAddress.isValid(a) || IPAddress.isValidWithNetMask(a);
            if (!res) {
                break;
            }
        }
        return res;
    }

    public static boolean isValidDNSNameList(String nameList) {
        boolean res = true;
        String[] names = nameList.split(",");
        String pattern = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";
        for (String n : names) {
            res = n.matches(pattern);
            if (!res) {
                break;
            }
        }
        return res;
    }

    public byte[] getActorId() {
        return actorID;
    }
    public String getActorIdAsHex() {
        return Hex.encode(actorID);
    }

    public void setActorId(byte[] id) {
        actorID = id;
        csrData.setSubjectAttribute("UID", Hex.encode(actorID));
    }

    public AuthorityID getAuthorityId() {
        return authorityID;
    }

    public void setAuthorityId(byte[] id) {
        authorityID = new AuthorityID(id);
        csrData.setSubjectAttribute("businessCategory", Hex.encode(authorityID.getAuthorityID()));
    }

    public void setAuthorityId(AuthorityID authID) {
        this.authorityID = authID;
        csrData.setSubjectAttribute("businessCategory",Hex.encode(authorityID.getAuthorityID()));
    }

    public String getCN() {
        String res = csrData.getSubjectAttribute("CN");
        if (res == null) {
            res = "";
        }
        return res;
    }

    public void setCN(String cn) {
        csrData.setSubjectAttribute("CN", cn);
    }

    public String getEmial() {
        String res = csrData.getSubjectAttribute("emailAddress");
        if (res == null) {
            res = "";
        }
        return res;
    }

    public void setEmail(String email) {
        csrData.setSubjectAttribute("emailAddress", email);
    }

    public String getIP() {
        return csrData.getExtendedAttribute("subjaltnames.ipaddress");
    }

    public void setIP(String ip) {
        if (ip != null && !ip.isEmpty()) {
            if (isValidIPAddresList(ip)) {
                csrData.setExtendedAttribute("subjaltnames.ipaddress", ip);
            } else {
                throw new IllegalArgumentException("Invalid IP4 or IP6 addres: " + ip);
            }
        }
    }

    public String getDNSNames() {
        return csrData.getExtendedAttribute("subjaltnames.dnsname");
    }

    public void setDNSNames(String n) {
        if (n != null && !n.isEmpty()) {
            if (isValidDNSNameList(n)) {
                csrData.setExtendedAttribute("subjaltnames.dnsname", n);
            } else {
                throw new IllegalArgumentException("Invalid DNS name: " + n);
            }
        }
    }

    public String getOrgUnit() {
        return csrData.getSubjectAttribute("OU");
    }

    public void setOrgUnit(String ou) {
        csrData.setSubjectAttribute("OU", ou);
    }

    public String getOrg() {
        return csrData.getSubjectAttribute("O");
    }

    public void setOrg(String o) {
        csrData.setSubjectAttribute("O", o);
    }

    public String getCountry() {
        return csrData.getSubjectAttribute("C");
    }

    public void setCountry(String c) {
        csrData.setSubjectAttribute("C", c);
    }

    public String getState() {
        return csrData.getSubjectAttribute("ST");
    }

    public void setState(String c) {
        csrData.setSubjectAttribute("ST", c);
    }

    public String getCity() {
        return csrData.getSubjectAttribute("L");
    }

    public void setCity(String c) {
        csrData.setSubjectAttribute("L", c);
    }

    public String getChallengePassword() {
        return challengePassword;
    }

    public void setChallengePassword(String challengePassword) {
        this.challengePassword = challengePassword;
    }

    public String getPemPKCS10() {
        String pem = "";
        try {
            csrData.processCertData(false);
            KeyPair kp;
            if (pvtKey != null) {
                kp = new KeyPair(pubKey, pvtKey);
            }else{
                kp = newKeyPair();
            }
            X509CertOperations certOps = factory.getX509CertOperations();
            PKCS10CertificationRequest cr = certOps.createX509CertificateRequest(kp, csrData, false, challengePassword);
            pem = kw.getCertificateRequestPEM(cr);
        } catch (IOException ex) {
            log.error("Can not generate PKSC10 CSR", ex);
        } catch (CryptoNotValidException ex) {
            log.error("Can not generate PKSC10 CSR, Invalid data", ex);
        }
        return pem;
    }

    public String getPrivateKeyPEM() {
        String pem = "";
        try {
            pem = kw.getPvtKeyPEM(pvtKey);
        } catch (IOException ex) {
            log.error("Can not get PEM of private key", ex);
        }
        return pem;
    }
    

    public CertAndKey getSelfSignedX509PEM() {
        CertAndKey res=null;
        try {
            csrData.processCertData(true);
            KeyPair kp;
            if (pvtKey == null) {
                kp = newKeyPair();
                pubKey = kp.getPublic();
                pvtKey = kp.getPrivate();
            }else{
                kp = new KeyPair(pubKey, pvtKey);
            }
            X509CertOperations certOps = factory.getX509CertOperations();            
            X509Certificate cert = certOps.createSelfSignedX509v3(kp, csrData);
            res = new CertAndKey(cert, pvtKey);
        } catch (CryptoNotValidException | IOException ex) {
            log.error("Can not generate self-signed PEM", ex);
        }
        return res;
    }

    @Override
    public String toString() {
        String res = "X.509 Certificate:\n";
        res += "CN=" + getCN() + "\n"
                + "ActorID=" + Hex.encode(getActorId()) + "\n";
        res += "emailAddress=" + getEmial() + "\n";
        res += "Country=" + getCountry() + " State/Province=" + getState()
                + " City=" + getCity();
        res += "Organization=" + getOrg() + " Org. Unit=" + getOrgUnit() + "\n";
        res += "IP address=" + getIP() + "\n";
        res += "DNS names=" + getDNSNames() + "\n";
        return res;
    }

    private KeyPair newKeyPair() {
        KeyGenerator kg = factory.getKeyGenerator();
        KeyPair kp = kg.generateKeys();  
        return kp;
    }

}
