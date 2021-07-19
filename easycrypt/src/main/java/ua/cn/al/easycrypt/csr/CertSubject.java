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

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * Utility class to work with certificate subject attributes
 * @author alukin@gmail.com
 */
public class CertSubject {
    static BCStyle bcStyle = new BCStrictStyle();
    
    static public Map<String,String> byNames(X500Name subj){
        Map<String,String> res = new HashMap<>();
        for(RDN r: subj.getRDNs()){ 
            AttributeTypeAndValue ata[] = r.getTypesAndValues();
            for(AttributeTypeAndValue a: ata){               
                res.put(oidToName(a.getType()), a.getValue().toString());
            }          
        }           
        return res;
    }
    
    static public Map<ASN1ObjectIdentifier,String> byOID(X500Name subj){
        Map<ASN1ObjectIdentifier,String> res = new HashMap<>();
        //usually there's only one RDN
        for(RDN r: subj.getRDNs()){ 
            AttributeTypeAndValue ata[] = r.getTypesAndValues();
            for(AttributeTypeAndValue a: ata){               
                res.put(a.getType(), a.getValue().toString());
            }          
        }       
        return res;
    }
    
    static public String oidToName(ASN1ObjectIdentifier oid){
        String res = bcStyle.oidToDisplayName(oid);
        return res;
    }
    
    static public ASN1ObjectIdentifier nameToOid(String attrName){
        ASN1ObjectIdentifier res = bcStyle.attrNameToOID(attrName.toLowerCase());
        return res;
    }
    
    static public Map<String, String> byNamesFromPrincipal(Principal p) {
        String separator =",";
        Map<String,String> res = new HashMap<>();
        String namesValues = p.toString();
                //In some cases we may have "+" as separator
        if(namesValues.indexOf('+')>0){
            separator="+";
        }
        //TODO: dow we have cases with "," and "+"? Do we have cases with "/" ?
        String nvpa[] = namesValues.split(separator);
        for(String nvp: nvpa){
            String nv[] = nvp.split("=");
            res.put(nv[0].trim(), nv[1].trim());
        }
        return res;
    }

}
