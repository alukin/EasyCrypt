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

package ua.cn.al.easycrypt.dataformat;

/**
 * Class that represents decryption result of AEADPlain (unencrypted part) and encrypted part of message
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 

 */
public class AEADPlain {
    /**
     * plain part of AEADPlain message
     */
    public byte[] plain;
    /**
     * decrypted part of AEADPlain message
     */
    public byte[] decrypted;
    /**
     * indicator of correctness
     */
    public boolean hmacOk;
}
