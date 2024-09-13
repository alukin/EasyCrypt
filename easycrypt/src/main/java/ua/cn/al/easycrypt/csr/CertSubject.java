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
