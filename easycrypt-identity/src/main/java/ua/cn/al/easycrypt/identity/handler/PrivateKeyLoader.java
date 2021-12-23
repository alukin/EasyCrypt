/*

 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
 *
 * GNU General Public License for more details.
 */

package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.ExtCert;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.PrivateKey;

/**
 *
 * @author alukin@gmail.com
 */
public interface PrivateKeyLoader {
    PrivateKey loadAndCheckPrivateKey(InputStream is, ExtCert cert, String password);
    PrivateKey loadAndCheckPrivateKey(Path p, ExtCert cert, String password);
}
