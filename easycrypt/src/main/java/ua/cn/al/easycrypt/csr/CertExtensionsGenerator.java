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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * X.500 is total big crap and we need just selected attributes for X.509v3
 * certificates but we need it in ASN1/DER format... so This class creates
 * attributes by names and values
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CertExtensionsGenerator {

    private static final Logger log = LoggerFactory.getLogger(CertExtensionsGenerator.class);
    private final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
    private final List<GeneralName> generalNames = new ArrayList<>();
    private final Map<ASN1ObjectIdentifier,ASN1Encodable> arrMap = new HashMap<>();
    
    public enum SupportedExtensions {
        KEYPURPOSE,
        SUBJALTNAMES,
        SUBJATTR
    }

    public enum KeyPurposeValue {
        HOST,
        PERSONAL,
        SOFTSIGN
    }

    public enum SupportedAltNames {
        IPADDRESS,
        DNSNAME,
        DIRECTORYNAME,
        REGISTEREDID,
        OTHERNAME,
        EMAIL,
        EDIPARTYNAME,
        UNIFORMRESQOURCEID
        
    }

    void createDefaultExtensions(boolean allowCertSign) throws IOException {
        //Extension.subjectDirectoryAttributes
        //Extension.subjectInfoAccess
        //disable usage as CA key
        extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(allowCertSign));
    }

    private boolean processKeyPurpose(String value) throws IOException {
        boolean res = true;
        try {
            KeyPurposeValue kpv = KeyPurposeValue.valueOf(value.toUpperCase());
            switch (kpv) {
                case HOST: {
                    extensionsGenerator.addExtension(
                            Extension.keyUsage, true, new KeyUsage(
                                    KeyUsage.digitalSignature
                                    | KeyUsage.keyAgreement
                                    | KeyUsage.dataEncipherment)
                    );
                    extensionsGenerator.addExtension(
                            Extension.extendedKeyUsage,
                            true,
                            new ExtendedKeyUsage(
                                    new KeyPurposeId[]{
                                        KeyPurposeId.id_kp_clientAuth,
                                        KeyPurposeId.id_kp_serverAuth,
                                        KeyPurposeId.id_kp_emailProtection,
                                        KeyPurposeId.id_kp_ipsecTunnel,
                                        KeyPurposeId.id_kp_ipsecEndSystem
                                    }
                            ));
                }
                break;
                case PERSONAL: {
                    extensionsGenerator.addExtension(
                            Extension.keyUsage, true, new KeyUsage(
                                    KeyUsage.digitalSignature
                                    | KeyUsage.dataEncipherment)
                    );
                    extensionsGenerator.addExtension(
                            Extension.extendedKeyUsage,
                            true,
                            new ExtendedKeyUsage(
                                    new KeyPurposeId[]{
                                        KeyPurposeId.id_kp_clientAuth,
                                        KeyPurposeId.id_kp_smartcardlogon,
                                        KeyPurposeId.id_kp_emailProtection,
                                        KeyPurposeId.id_kp_ipsecUser
                                    }
                            ));
                }
                break;

                case SOFTSIGN: {
                    extensionsGenerator.addExtension(
                            Extension.keyUsage, true, new KeyUsage(
                                    KeyUsage.digitalSignature
                                    | KeyUsage.dataEncipherment)
                    );
                    extensionsGenerator.addExtension(
                            Extension.extendedKeyUsage,
                            true,
                            new ExtendedKeyUsage(
                                    new KeyPurposeId[]{
                                        KeyPurposeId.id_kp_codeSigning,
                                        KeyPurposeId.id_kp_timeStamping,
                                        KeyPurposeId.id_kp_emailProtection
                                    }
                            ));
                }
            }
        } catch (IllegalArgumentException ex) {
            log.error("Certificate type: {} is not supported, cause: {}", value, ex.getMessage());
            res = false;
        }
        return res;
    }

    private boolean processAltNames(String key, String value) throws IOException {
        boolean res = true;
        try {
            SupportedAltNames altname = SupportedAltNames.valueOf(key.toUpperCase());
            GeneralName name = null;

            switch (altname) {
                case DIRECTORYNAME:
                    name = new GeneralName(GeneralName.directoryName, value);
                    break;
                case DNSNAME:
                    name = new GeneralName(GeneralName.dNSName, value);
                    break;
                case EDIPARTYNAME:
                    name = new GeneralName(GeneralName.ediPartyName, value);
                    break;
                case EMAIL:
                    name = new GeneralName(GeneralName.rfc822Name, value);
                    break;
                case IPADDRESS:
                    name = new GeneralName(GeneralName.iPAddress, value);
                    break;
                case OTHERNAME:
                    name = new GeneralName(GeneralName.otherName, value);
                    break;
                case REGISTEREDID:
                    name = new GeneralName(GeneralName.registeredID, value);
                    break;
                case UNIFORMRESQOURCEID:    
                    name = new GeneralName(GeneralName.uniformResourceIdentifier, value);
                    break;
            }
            if (name != null) {
                generalNames.add(name);
            }
        } catch (IllegalArgumentException ex) {
            log.error("AltName extension: {} is not supported, cause: {}", key, ex.getMessage());
            res = false;
        }

        return res;
    }

    private boolean processDirectoryAttribute(String aname, String value) {
        boolean res=true;
        try{
           ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(aname);
           //TODO: encode value?
        }catch(IllegalArgumentException ex){
            log.error("Can not construct OID from string: {} cause: {}", aname, ex.getMessage());
            res=false;
        }   
        return res;
    }

    boolean processAttribute(String attrName, String value) throws IOException {
        boolean res = false;
        int idx = attrName.indexOf('.');
        if (idx < 0) {
            idx = attrName.length();
        }
        String extName = attrName.substring(0, idx);
        try {
            SupportedExtensions ext = SupportedExtensions.valueOf(extName.toUpperCase());
            switch (ext) {
                case KEYPURPOSE: {
                    res = processKeyPurpose(value);
                }
                break;
                case SUBJALTNAMES: {
                    String ana = attrName.substring(extName.length()+1);
                    res = processAltNames(ana, value);
                }
                break;
                case SUBJATTR: {
                    String ana = attrName.substring(extName.length()+1);
                    res = processDirectoryAttribute(ana, value);
                }
            }
        } catch (IllegalArgumentException ex) {
            log.error("Extension attribute: {} is not supported, cause: {}",extName, ex.getMessage());
            res = false;
        }
        return res;
    }

    Extensions generate() throws IOException {

        GeneralNames subAtlNames = new GeneralNames(
                generalNames.toArray(new GeneralName[generalNames.size()])
        );
        extensionsGenerator.addExtension(
                Extension.subjectAlternativeName, true, subAtlNames);
        
        // TODO: add subjectDirectoryAttributes
        // extensionsGenerator.addExtension(Extension.subjectDirectoryAttributes, false,new ASN1Encodable[0b10])

        return extensionsGenerator.generate();
    }

}
