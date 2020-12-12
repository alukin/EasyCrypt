/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
package io.firstbridge.cryptoutils;

import ua.cn.al.easycrypt.csr.CertSubject;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Certificate and CSR displaying utilites methods
 * @author alukin@gmail.com
 */
public class CertDisplayUtils {
    private final static String LS=System.lineSeparator();
    
    public static  String csrToString(PKCS10CertificationRequest cr) {
        String res="";        
        res+="Subject: "+cr.getSubject()+LS;
        X500Name n = cr.getSubject();
        Map<ASN1ObjectIdentifier,String> rdnAttr = CertSubject.byOID(n);
        for(ASN1ObjectIdentifier a: rdnAttr.keySet()){
            res+="\tRDN: "+ CertSubject.oidToName(a) +" ("+a.getId() + ") = " + rdnAttr.get(a)+LS;
        }
        res+="Atrtributes:"+LS;
        for(Attribute a:cr.getAttributes()){
            res+="\t"+a.getAttrType().toString() + ":"+LS;
            for(ASN1Encodable av: a.getAttributeValues()){
                res+="\t\t"+av.toASN1Primitive().toString();
            }
        }
        return res;        
    } 
}
