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
