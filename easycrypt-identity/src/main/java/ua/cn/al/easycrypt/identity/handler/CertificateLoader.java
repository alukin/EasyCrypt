/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU LESSER GENERAL PUBLIC LICENSE
 * as published by the Free Software Foundation, version 3
 * of the License.
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
