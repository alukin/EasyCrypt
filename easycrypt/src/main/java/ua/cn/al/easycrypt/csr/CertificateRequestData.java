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

import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoNotValidException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * @author Oleksiy Lukin alukin@gmail.com
 * REFERENCES
 * https://tools.ietf.org/html/rfc2986 PKCS #10: Certification Request Syntax Specification
 * Version 1.7
 */
public class CertificateRequestData {
    private static final Logger log = LoggerFactory.getLogger(CertificateRequestData.class);
    private static final Map<String, String> sa = setSupportedAttributes();
    public static final String SUBJ_PRFX = "subject.";
    public static final String ATTR_PRFX = "attribute.";

    static{
        CryptoConfig.getProvider();
    }

    public enum CSRType {
        HOST,
        PERSON,
        SOFTSIGN
    }

    private CertExtensionsGenerator attrGen;

    private X500Name subject;
    private Extensions extensions;

    private final Map<String, String> certDataMap = new HashMap<>();

    private static Map<String, String> setSupportedAttributes() {
        Map<String, String> sa = new HashMap<>();
        sa.put(SUBJ_PRFX + "CN", "Canonical common name, main name of subject. String(64). OID=2.5.4.3");
        sa.put(SUBJ_PRFX + "C", "Country code. String(2). OID=2.5.4.6");
        sa.put(SUBJ_PRFX + "O", "Organization name. String(64). OID=2.5.4.10");
        sa.put(SUBJ_PRFX + "T", "Title. String(64). OID=2.5.4.12");
        sa.put(SUBJ_PRFX + "OU", "Organizational unit. String(64). OID=2.5.4.11");
        sa.put(SUBJ_PRFX + "L", "Location, e.g. City name. String(64). OID=2.5.4.7");
        sa.put(SUBJ_PRFX + "ST", "State. String(64). OID=2.5.4.8");
        sa.put(SUBJ_PRFX + "SERIALNUMBER", "Serial number of subject. String(64). OID=2.5.4.5");
        sa.put(SUBJ_PRFX + "E", "Email adderes, String. OID=1.2.840.113549.1.9.1");
        sa.put(SUBJ_PRFX + "DC", "Domain component, one component of Domain name. String. (Coma separated list here). OID=0.9.2342.19200300.100.1.25");
        sa.put(SUBJ_PRFX + "UID", "LDAP User(Entity) id. String(256). OID=0.9.2342.19200300.100.1.1");
        sa.put(SUBJ_PRFX + "STREET", "Street address. String(64), OID=2.5.4.9");
        sa.put(SUBJ_PRFX + "SURNAME", "Surname. String. OID=2.5.4.4");
        sa.put(SUBJ_PRFX + "GIVENNAME", "First name. String. OID=2.5.4.42");
        sa.put(SUBJ_PRFX + "INITIALS", "Contains the initials of some or all of an individual's names, but not the surname(s). Strin. OID=2.5.4.43");
        sa.put(SUBJ_PRFX + "GENERATION", "Generation information to qualify an individual's name (e.g. Paul IV). String. OID=2.5.4.44");
        sa.put(SUBJ_PRFX + "unstructuredAddress", "Unstructured address. String. OID=1.2.840.113549.1.9.8");
        sa.put(SUBJ_PRFX + "unstructuredName", "Unstructured name. String. OID=1.2.840.113549.1.9.2");
        sa.put(SUBJ_PRFX + "UniqueIdentifier", "Unique identificator, OID 2.5.4.45");
        sa.put(SUBJ_PRFX + "DN", "Distinguished name. String. (Coma separated) OID=2.5.4.46");
        sa.put(SUBJ_PRFX + "Pseudonym", "According to RFC3039: \"pseudonym from (forthcoming) X.520\" OID=2.5.4.65");
        sa.put(SUBJ_PRFX + "PostalAddress", "RFC 3039 PostalAddress - SEQUENCE (6) of String(30). OID=2.5.4.16");
        sa.put(SUBJ_PRFX + "NameAtBirth", "ISIS-MTT NameAtBirth - String(64). OID=1.3.36.8.3.14");
        sa.put(SUBJ_PRFX + "CountryOfCitizenship", "RFC 3039 CountryOfCitizenship. String(2) ISO 3166 OID=1.3.6.1.5.5.7.9.4");
        sa.put(SUBJ_PRFX + "CountryOfResidence", "RFC 3039 CountryOfResidence. String(2) ISO 3166 OID=1.3.6.1.5.5.7.9.5");
        sa.put(SUBJ_PRFX + "Gender", "M or F, one letter. OID=1.3.6.1.5.5.7.9.3");
        sa.put(SUBJ_PRFX + "PlaceOfBirth", "RFC 3039 PlaceOfBirth. String(SIZE(128) OID=1.3.6.1.5.5.7.9.2");
        sa.put(SUBJ_PRFX + "DateOfBirth", "RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z. OID=1.3.6.1.5.5.7.9.1");
        sa.put(SUBJ_PRFX + "PostalCode", "Postal code. String(40). OID=2.5.4.17");
        sa.put(SUBJ_PRFX + "BusinessCategory", " specifies information concerning the occupation of some common objects, e.g., people. Sting(128)."
                + "OID=2.5.4.15");
        sa.put(SUBJ_PRFX + "TelephoneNumber", "Telephone Number. CCITT Rec. E.123 . String. OID=2.5.4.20");
        sa.put(SUBJ_PRFX + "Name", "Supertype attribute. OID=2.5.4.41");
        sa.put(SUBJ_PRFX + "organizationIdentifier", "Holds an identification of an organization different from the organization. String.  OID=2.5.4.97");
        sa.put(ATTR_PRFX + "subjaltnames.registeredid", "TODO:  addd description, OID=1.3.6.78.91.235");
        sa.put(ATTR_PRFX + "subjaltnames.dnsname", " DNS name");
        sa.put(ATTR_PRFX + "subjaltnames.ipaddress", "IP address");
        return sa;
    }

    public CertificateRequestData(CSRType type) {
        setSupportedAttributes();
        setCSRType(type);
    }

    public CertificateRequestData() {
        this(CSRType.HOST);
    }

    public X500Name getSubject() {
        return subject;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public final void setCSRType(CSRType type) {
        switch (type) {
            case HOST: {
                emptyParamMapForHost();
            }
            break;
            case PERSON: {
                emptyParamMapForPerson();
            }
            break;
            case SOFTSIGN: {
                emptyParamMapForSoftSigner();
            }
        }
    }

    public void addProperty(String key, String value) {
        certDataMap.put(key, value);
    }

    public void processCertData(boolean allowCertSign) throws CryptoNotValidException, IOException {
        BCStyle bcStyle = new BCStrictStyle();
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        attrGen = new CertExtensionsGenerator();
        for (String key : certDataMap.keySet()) {
            String value = certDataMap.get(key);
            if (value == null || value.isEmpty()) {
                continue;
            }
            if (key.startsWith(SUBJ_PRFX)) {
                String an = key.substring(SUBJ_PRFX.length());
                an = an.toLowerCase();
                ASN1ObjectIdentifier oid = bcStyle.attrNameToOID(an);
                String[] values = value.split(",");
                for (String v : values) {
                    x500NameBld.addRDN(oid, v);
                }
            } else if (key.startsWith(ATTR_PRFX)) {
                String attr_name = key.substring(ATTR_PRFX.length());
                if (!attrGen.processAttribute(attr_name, value)) {
                    throw new CryptoNotValidException("Attribute pair:" + attr_name + " : " + value + " is not supported");
                }
            } else {
                log.error("Unknown property: {}", key);
            }
        }
        subject = x500NameBld.build();
        try {
            attrGen.createDefaultExtensions(allowCertSign);
            extensions = attrGen.generate();
        } catch (IOException ex) {
            log.error("Exception inside of extension generator", ex);
        }
    }

    public static CertificateRequestData fromMap(Map<String, String> cd, CSRType type) {
        CertificateRequestData res = new CertificateRequestData(type);
        res.certDataMap.putAll(cd);
        return res;
    }

    public static CertificateRequestData fromProperty(Properties p, CSRType type) {
        Map<String, String> cd = new HashMap<>();
        for (Object key : p.keySet()) {
            cd.put(key.toString(), p.getProperty(key.toString()));
        }
        return fromMap(cd, type);
    }

    public final void emptyParamMapForHost() {
        certDataMap.clear();
        // see BCStyle.java
        certDataMap.put(SUBJ_PRFX + "CN", ""); // Canonical name
        certDataMap.put(SUBJ_PRFX + "O", ""); //Organization
        certDataMap.put(SUBJ_PRFX + "OU", ""); //Organizational unit
        certDataMap.put(SUBJ_PRFX + "L", ""); //Locality name (e.g. city)
        certDataMap.put(SUBJ_PRFX + "C", ""); // 2-char country code
        certDataMap.put(SUBJ_PRFX + "emailAddress", "");
        // certDataMap.put(SUBJ_PRFX + "SERIALNUMBER", ""); //device serial number, or host ID, or other case
        certDataMap.put(SUBJ_PRFX + "UID", ""); //LDAP user Id or entity ID
        //This attribute is fixed for cert type
        certDataMap.put("attribute.keypurpose", "host"); //
        // Attributes that should be defined
        certDataMap.put("attribute.subjaltnames.dnsname", "");
        //      certDataMap.put("attribute.subjaltnames.registeredid","");
    }

    public final void emptyParamMapForPerson() {
        certDataMap.clear();
        // see BCStyle.java
        certDataMap.put(SUBJ_PRFX + "CN", ""); // Canonical name
        certDataMap.put(SUBJ_PRFX + "O", ""); //Organization
        certDataMap.put(SUBJ_PRFX + "OU", ""); //Organizational unit
        certDataMap.put(SUBJ_PRFX + "L", ""); //Locality name (e.g. city)
        certDataMap.put(SUBJ_PRFX + "C", ""); // 2-char country code
        certDataMap.put(SUBJ_PRFX + "emailAddress", "");
        // certDataMap.put(SUBJ_PRFX + "SERIALNUMBER", ""); //device serial number, or host ID or other case
        certDataMap.put(SUBJ_PRFX + "UID", ""); //LDAP user Id or entity Id
        //This attribute is fixed for cert type
        certDataMap.put("attribute.KEYPURPOSE", "personal");
    }

    public final void emptyParamMapForSoftSigner() {
        certDataMap.clear();
        // see BCStyle.java
        certDataMap.put(SUBJ_PRFX + "CN", ""); // Canonical name
        certDataMap.put(SUBJ_PRFX + "O", ""); //Organization
        certDataMap.put(SUBJ_PRFX + "OU", ""); //Organizational unit
        certDataMap.put(SUBJ_PRFX + "L", ""); //Locality name (e.g. city)
        certDataMap.put(SUBJ_PRFX + "C", ""); // 2-char country code
        //       certDataMap.put(SUBJ_PRFX + "UNIQUE_IDENTIFIER", ""); //naming attribute from X520name
        certDataMap.put(SUBJ_PRFX + "emailAddress", "");
        // certDataMap.put(SUBJ_PRFX + "SERIALNUMBER", ""); //device serial number, or host ID or other case
        certDataMap.put(SUBJ_PRFX + "UID", ""); //LDAP user Id or entity Id
        //This attribute is fixed for cert type
        certDataMap.put("attribute.KEYPURPOSE", "softsign");
    }

    public List<String> checkNotSetParameters() {
        List<String> res = new ArrayList<>();
        for (String key : certDataMap.keySet()) {
            String value = certDataMap.get(key);
            if (value == null || value.isEmpty()) {
                res.add(key);
            }
        }
        return res;
    }

    public static Map<String, String> getSupportedAttributesHelp() {
        return sa;
    }

    public String findName(String aname) {
        String res = "";
        for (String key : sa.keySet()) {
            if (key.equalsIgnoreCase(aname)) {
                res = key;
                break;
            }
        }
        return res;
    }

    public boolean isAttributeSupported(String aname) {
        return !findName(aname).isEmpty();
    }

    public void setSubjectAttribute(String name, String value) {
        if (value == null || value.isEmpty() || value.trim().isEmpty()) {
            return;
        }
        String aname = SUBJ_PRFX + name;
        String rname = findName(aname);
        if (!rname.isEmpty()) {
            certDataMap.put(rname, value);
        } else {
            log.warn("Attribute is not supported: {}", name);
        }
    }

    public String getSubjectAttribute(String name) {
        String aname = SUBJ_PRFX + name;
        String rname = findName(aname);
        String res = certDataMap.get(rname);
        if (res == null) {
            res = "";
        }
        return res;
    }

    public String getExtendedAttribute(String name) {
        String aname = ATTR_PRFX + name;
        String rname = findName(aname);
        String res = certDataMap.get(rname);
        if (res == null) {
            res = "";
        }
        return res;
    }

    public void setExtendedAttribute(String name, String value) {
        if (value == null || value.isEmpty() || value.trim().isEmpty()) {
            return;
        }
        String aname = ATTR_PRFX + name;
        String rname = findName(aname);
        if (!rname.isEmpty()) {
            certDataMap.put(rname, value);
        } else {
            log.warn("Attribute is not supported: {}", name);
        }
    }
}
