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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * @author alukin@gmail.com
 */
public class ActorType {
    //actor types
    public static final int NODE = 1;
    public static final int SERVICE = 2;
    public static final int PERSON = 3;
    //actor sub-types for NODE
    public static final int NODE_REGULAR = 0;
    public static final int NODE_ARCHIVE = 1;
    public static final int NODE_CERTIFIED_STORAGE = 2;
    public static final int NODE_REGULAR_STORAGE = 3;
    //actor sub-types for services
    public static final int SERVICE_NONE = 0;
    public static final int SERVICE_EXCHANE = 1;
    public static final int SERVICE_WEBSITE = 2;
    public static final int SERVICE_CDN = 3;
    //actor sub-types for PERSON
    public static final int PERSON_UNKNOWN = 0;
    public static final int PERSON_DEVELOPER = 16;
    public static final int PERSON_RELESE_ENG = 17;
    public static final int PERSON_QUALITY_ASSURANCE = 18;
    public static final int PERSON_DEV_MANAGEMENT = 19;
    public static final int PERSON_DEVOPS = 20;
    public static final int PERSON_MARKETING = 21;

    public static final int PERSON_PRIVILEGED_USER = 128;
    
    private int[] at = {0, 0};

    public ActorType(int atype) {
        ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(atype);
        at[0] = bb.get(2);
        at[1] = bb.get(3);
    }

    public ActorType() {
    }

    public Integer getValue() {
        return at[0] << 8 | at[1];
    }

    public Integer getType() {
        return at[0];
    }

    public void setType(int t) {
        at[0] = t & 0xFF;
    }

    public Integer getSubType() {
        return at[1];
    }

    public void setSubType(int t) {
        at[1] = t & 0xFF;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (!ActorType.class.isAssignableFrom(obj.getClass())) {
            return false;
        }

        final ActorType other = (ActorType) obj;
        if ((this.at == null) ? (other.at != null) : !Arrays.equals(this.at, other.at)) {
            return false;
        }

        return true;
    }

    @Override
    //generated by IDE
    public int hashCode() {
        int hash = 3;
        hash = 43 * hash + Arrays.hashCode(this.at);
        return hash;
    }

}
