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
package ua.cn.al.easycrypt.container;

import java.util.List;

/**
 * JSON-based encrypted general purpose wallet
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class CryptedWallet extends GenericWallet<CryptedWalletModel>{

    public CryptedWallet() {
        super(new CryptedWalletModel());
    }

    public void addData(DataRecord dr) {
        wallet.data.add(dr);
    }

    public void addKey(KeyRecord kr) {
        wallet.keys.add(kr);
    }

    public DataRecord getData(String alias) {
        DataRecord res = null;
        for (DataRecord dr : wallet.data) {
            if (alias.equals(dr.alias)) {
                res = dr;
                break;
            }
        }
        return res;
    }

    public KeyRecord getKeys(String alias) {
        KeyRecord res = null;
        for (KeyRecord dr : wallet.keys) {
            if (alias.equals(dr.alias)) {
                res = dr;
                break;
            }
        }
        return res;
    }

    public List<KeyRecord> getAllKeys() {
        return wallet.keys;
    }

    public List<DataRecord> getAllData() {
        return wallet.data;
    }

  }
