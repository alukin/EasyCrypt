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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON Wallet model
 * @author Oleksiy Lukin alukin@gmail.com
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CryptedWalletModel {
    public String version = "1.0.0";
    public String name="noName";
    public List<KeyRecord> keys=new ArrayList<>();
    public List<DataRecord> data = new ArrayList<>();
}
