/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
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
