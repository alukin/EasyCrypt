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
package ua.cn.al.easycrypt.cryptoutils;

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
