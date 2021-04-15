/*
 * Copyright (C) 2021 Oleksiy Lukin 
 *
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
package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.ExtCert;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;

/**
 *
 * @author alukin@gmail.com
 */
public interface CertificateLoader {
    ExtCert loadCert(InputStream is);
    ExtCert loadCert(Path p);
    List<ExtCert> loadCertsFromDir(Path p);
}
