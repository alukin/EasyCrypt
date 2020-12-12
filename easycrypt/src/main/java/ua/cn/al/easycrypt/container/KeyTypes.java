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
 * Key types indicator
 * @author OleksiyLukin serhiy.lymar@gmail.com 
 */
public enum KeyTypes {
    /**
     * PEM encoded public key, private key, certificate, etc
     */
    PEM,
    BITCOIN,
    ETHEREUM,
    OTHER    
}
