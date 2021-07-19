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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

/**
 * AUthority ID is set of bits that classifies  crypto actors and
 * actor's capabilities.
 * Most significant 16 bit is abstract net ID. Least significant
 * bytes meaning si following. Les's number each of 16 bytes as following:
 * 15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
 * So bytes assigned to:
 * 01 00 - actor type (01) and subtype (00)
 * 03 02 - region code, not used yet
 * 05 04 - business code, not used yet
 * 07 06 - authority code, planned for usage together with business code for delegation tree
 * 11 10 09 08 - operation code, planned for usage as operations permission mask
 * 15 14 13 12  - supplemental  code, reserved for future use
 *
 * @author alukin@gmail.com
 */
public class AuthorityID {
    static String[] names={"BUSINESSCATEGORY", "OID.2.5.4.15", "2.5..15"};
    
    /**
     * Length of AuthorityID in bytes, 256 bit
     */
    public static final int ID_LENGHT = 256/8; //32 bytes, 256 bit

    /**
     * order is natural: [0] is less significant byte
     */
    private byte[] authorityID;
    
    private void allocate() {
        authorityID = new byte[ID_LENGHT];
        byte zero = 0;
        Arrays.fill(authorityID, zero);
    }
    
    public AuthorityID() {
        allocate();
    }

    public AuthorityID(byte[] a) {
        
        allocate();
        //make byte by byte copy starting from last siginificant byte
        int idx_dst = ID_LENGHT - 1;
        int idx_src = a.length - 1;
        while (idx_dst >=0 && idx_src >=0) {
            authorityID[idx_dst] = a[idx_src];
            idx_src--;
            idx_dst--;
        }
    }
    
    public static AuthorityID fromAttributes(Map<String,String> attr){
        String value = null;
        for(String an: names){
            value = attr.get(an);
            if(value!=null){
                break;
            }
        }        
        AuthorityID res;
        if(value==null){
            res = new AuthorityID();
        }else{
            byte[] bv = Hex.decode(value);
            res = new AuthorityID(bv);
        }
        return res;
    }
    

    public byte[] get() {
        return authorityID;
    }

    public byte[] getAuthorityID() {
        return authorityID;
    }

    /**
     * ActorType and ActorSubType are first 2 least significant bytes of
     * AuthorityID respectively
     *
     * @return 2 bytes of ActorType wrapped to 4 bytes of int
     */
    public int getActorTypeAsInt() {
        int res = authorityID[ID_LENGHT-1-1] << 8 | authorityID[ID_LENGHT-1-0];
        return res;
    }

    /**
     * Sets ActorType and ActorSubType as first 2 least significant bytes of
     * AuthorityID respectively
     *
     * @param at 2 bytes wrapped in 2 least significant bytes of int
     */
    public void setActorType(int at) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(at);        
        authorityID[ID_LENGHT-1-1] = bb.get(2);
        authorityID[ID_LENGHT-1-0] = bb.get(3);
    }

    /**
     * ActorType and ActorSubType are first 2 least significant bytes of
     * AuthorityID respectively
     *
     * @return ActorType and ActorSubType wrapped in ActorType class
     */
    public ActorType getActorType() {
        return new ActorType(getActorTypeAsInt());
    }

    /**
     * Sets ActorType and ActorSubType as first 2 least significant bytes of
     * uthorityID respectively
     *
     * @param vat ActorType class hat wraps those 2 bytes
     */
    public void setActorType(ActorType vat) {
        AuthorityID.this.setActorType(vat.getValue());
    }

    /**
     * RegionCode is 2nd and 3rd least significant bytes of AuthorityID
     *
     * @return 2 bytes of RegionCode wrapped to 2 least significant bytes of int
     */
    public Integer getRegionCode() {
        int res = authorityID[ID_LENGHT-1-3] << 8 | authorityID[ID_LENGHT-1-2];
        return res;
    }

    /**
     * RegionCode is 2nd and 3rd least significant bytes of AuthorityID
     *
     * @param rc 2 bytes of RegionCode wrapped to 2 least significant bytes of
     *           int
     */
    public void setRegionCode(int rc) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(rc);
        authorityID[ID_LENGHT-1-3] = bb.get(2);
        authorityID[ID_LENGHT-1-2] = bb.get(3);
    }

    /**
     * BusinessCode is 4th and 5th most significant bytes of AuthorityID
     *
     * @return 2 bytes of BusinessCode wrapped to 2 least significant bytes of
     * int
     */
    public Integer getBusinessCode() {
        int res = authorityID[ID_LENGHT-1-5] << 8 | authorityID[ID_LENGHT-1-4];
        return res;
    }

    /**
     * BusinessCode is 4th and 5th most significant bytes of AuthorityID
     *
     * @param bc 2 bytes of BusinessCode wrapped to 2 least significant bytes of
     *           int
     */
    public void setBusinessCode(int bc) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(bc);
        authorityID[ID_LENGHT-1-5] = bb.get(2);
        authorityID[ID_LENGHT-1-4] = bb.get(3);
    }

    /**
     * AuthorityCode is 6th and 7th most significant bytes of AuthorityID
     *
     * @return 2 bytes of AuthorityCode wrapped to 2 least significant bytes of
     * int
     */
    public Integer getAuthorityCode() {
        int res = authorityID[ID_LENGHT-1-7] << 8 | authorityID[ID_LENGHT-1-6];
        return res;
    }

    /**
     * AuthorityCode is 6th and 7th most significant bytes of AuthorityID
     *
     * @param bc 2 bytes of AuthorityCode wrapped to 2 least significant bytes
     *           of int
     */
    public void setAuthorityCode(int bc) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(bc);
        authorityID[ID_LENGHT-1-7] = bb.get(2);
        authorityID[ID_LENGHT-1-6] = bb.get(3);
    }

    public long getOperationCode() {
        long res = authorityID[ID_LENGHT-1-11] << 24 | authorityID[ID_LENGHT-1-10] << 16 
                 | authorityID[ID_LENGHT-1-9] << 8 | authorityID[ID_LENGHT-1-8];
        return res;
    }

    public void setOperationCode(long oc) {
        ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(oc);
        authorityID[ID_LENGHT-1-11] = bb.get(4);
        authorityID[ID_LENGHT-1-10] = bb.get(5);
        authorityID[ID_LENGHT-1-9] = bb.get(6);
        authorityID[ID_LENGHT-1-8] = bb.get(7);
    }

    public Long getSuplementalCode() {
        long res = authorityID[ID_LENGHT-1-15] << 24 | authorityID[ID_LENGHT-1-14] << 16 
                 | authorityID[ID_LENGHT-1-13] << 8 | authorityID[ID_LENGHT-1-12];
        return res;
    }

    public void setSuplementalCode(long sc) {
        ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(sc);
        authorityID[ID_LENGHT-1-15] = bb.get(4);
        authorityID[ID_LENGHT-1-14] = bb.get(5);
        authorityID[ID_LENGHT-1-13] = bb.get(6);
        authorityID[ID_LENGHT-1-12] = bb.get(7);
    }
    
    /** 
     * NetId is most significant 128 bit of AuthorityID
     * @return Network ID 
     */
    public byte[] getNetId(){
         int idx = ID_LENGHT/2;
         byte[] bb = Arrays.copyOfRange(authorityID, idx, ID_LENGHT);
         return bb;
    }
    
    /**
     * NetId is most significant 128 bit of AuthorityID
     * @param id 128 bit array in bigendian order
     */ 
    public void setNetId(byte[] id){
        int half = ID_LENGHT/2;
        int idx_dst = ID_LENGHT - 1;
        int idx_src = id.length - 1;
        while (idx_dst >=half) {
            byte v;
            if(idx_src>=0){
                v=id[idx_src];
            }else{
                v=0;
            }        
            authorityID[idx_dst] = v;
            idx_src--;
            idx_dst--;
        }
    }
    
    public void setNetId(UUID uuid){
        ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
        bb.putLong(uuid.getMostSignificantBits());
        bb.putLong(uuid.getLeastSignificantBits());       
    }
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (!AuthorityID.class.isAssignableFrom(obj.getClass())) {
            return false;
        }

        final AuthorityID other = (AuthorityID) obj;
        if ((this.authorityID == null) ? (other.authorityID != null) : !Arrays.equals(this.authorityID, other.authorityID)) {
            return false;
        }

        return true;
    }

    @Override
    //generated by IDE
    public int hashCode() {
        int hash = 5;
        hash = 89 * hash + Arrays.hashCode(this.authorityID);
        return hash;
    }



    @Override
    public String toString() {
        return Hex.encode(authorityID);
    }

}
