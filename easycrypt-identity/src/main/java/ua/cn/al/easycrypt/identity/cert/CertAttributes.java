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

import ua.cn.al.easycrypt.identity.utils.Hex;
import java.util.HashMap;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;

import java.util.List;
import java.util.Map;
import org.bouncycastle.util.Arrays;
import ua.cn.al.easycrypt.csr.CertSubject;

/**
 * PKCS#10 and X.509 attribute parser
 *
 * @author alukin@gmail.com
 */
public class CertAttributes {
    
    public static final String ACTOR_ID_ATTRIBUTE="UID";
    
    private byte[] actorId;
    private AuthorityID authorityId = new AuthorityID();
    private final List<String> ipAddList = null;
    Attribute[] attributes;
    Map<String,String> subjectAttributes = new HashMap<>();
    
    public CertAttributes() {
        actorId=new byte[CertBase.ACTOR_ID_LENGTH];
        byte zero = 0;
        Arrays.fill(actorId, zero);
    }

    public void setAttributes(Attribute[] aa) {
        attributes=aa;
    }

    public void setSubject(X500Name sn) throws CertException {
        subjectAttributes = CertSubject.byNames(sn);
    }
    
    public void setSubjectMap(Map<String,String> subject){
        subjectAttributes = subject;
        authorityId = AuthorityID.fromAttributes(subject);
    }
    
    public byte[] getActorId() {
        return actorId;
    }

    public void setActorId(byte[] id) {
        //make byte by byte copy starting from last siginificant byte
        int idx_dst = actorId.length- 1;
        int idx_src = id.length - 1;
        while (idx_dst >=0 && idx_src >=0) {
            actorId[idx_dst] = id[idx_src];
            idx_src--;
            idx_dst--;
        }        
        subjectAttributes.put(ACTOR_ID_ATTRIBUTE, Hex.encode(actorId));
    }

    public AuthorityID getAuthorityId() {
        return authorityId;
    }

    public void setAuthorityId(AuthorityID authorityId) {
        this.authorityId = authorityId;
        subjectAttributes.put("businnesCategory",Hex.encode(authorityId.get()));
    }

    public String getCn() {
        return subjectAttributes.get("CN");
    }

    public void setCn(String cn) {
        subjectAttributes.put("CN", cn);
    }

    public String getO() {
        return subjectAttributes.get("O");
    }

    public void setO(String o) {
        subjectAttributes.put("O", o);
    }

    public String getOu() {
        return subjectAttributes.get("OU");
    }

    public void setOu(String ou) {
        subjectAttributes.put("OU", ou);
    }

    public String getCountry() {
        return subjectAttributes.get("C");
    }

    public void setCountry(String country) {
       subjectAttributes.put("C", country);
    }

    public String getState() {
        return subjectAttributes.get("ST");
    }

    public void setState(String state) {
        subjectAttributes.put("ST", state);
    }

    public String getCity() {
        return subjectAttributes.get("L");
    }

    public void setCity(String city) {
        subjectAttributes.put("L", city);
    }

    public String geteMail() {
        String res=subjectAttributes.get("E");
        if(res==null){
            res=subjectAttributes.get("EMAILADDRESS");
        }
        return res;
    }

    public void seteMail(String eMail) {
        subjectAttributes.put("E", eMail);
    }

    List<String> IpAddresses() {
        return ipAddList;
    }

    @Override
    public String toString() {
     String LS =  System.lineSeparator();  
     String res="";   
     res+=" ActorID: "+ Hex.encode(actorId)+LS;
     res+=" AuthorityID: " + authorityId + LS;
     res+=" Attributes: "+LS;
     for (Map.Entry<String, String> entry : subjectAttributes.entrySet()) {
         res+="\t"+entry.getKey()+" = "+entry.getValue()+LS;
     }     
     return res;
    }
}
