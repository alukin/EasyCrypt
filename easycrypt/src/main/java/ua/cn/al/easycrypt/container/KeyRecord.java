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
package ua.cn.al.easycrypt.container;

/**
 * Record for keys storage
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class KeyRecord {
   public String alias; 
   public KeyTypes keyType;
   public String publicKey;
   public String pvtEncryptParam;
   public String privateKy;
   public long timestamp;
}
