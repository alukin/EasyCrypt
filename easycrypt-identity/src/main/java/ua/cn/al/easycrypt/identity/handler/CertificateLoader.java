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
