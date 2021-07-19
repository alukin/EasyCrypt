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

package ua.cn.al.easycrypt.identity.handler;

import ua.cn.al.easycrypt.identity.cert.CertException;
import ua.cn.al.easycrypt.identity.cert.CertKeyPersistence;
import ua.cn.al.easycrypt.identity.cert.ExtCert;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class CertificateLoaderImpl implements CertificateLoader {

    private List<ExtCert> readAllFromFs(Path path) throws IOException {
        try (FileSystem fileSystem = FileSystems.newFileSystem(path, ClassLoader.getSystemClassLoader())) {
            return loadCertsFromDir(fileSystem.getPath("/"));
        }
    }

    @Override
    public ExtCert loadCert(InputStream is) {
        ExtCert cert = null;
        try {
            cert = CertKeyPersistence.loadCertPEMFromStream(is);
        } catch (CertException | IOException e) {
            log.error("Unable to load certificate from stream", e);
        }
        return cert;
    }

    @Override
    public ExtCert loadCert(Path p) {
        ExtCert cert = null;
        try {
            cert = CertKeyPersistence.loadCertPEMFromPath(p.toAbsolutePath());
        } catch (CertException | IOException e) {
            log.debug("Unable to load certificate from " + p.toAbsolutePath(), e);
        }
        return cert;
    }

    @Override
    public List<ExtCert> loadCertsFromDir(Path p) {
                List<ExtCert> certs = new ArrayList<>();
        try {
            Files.walkFileTree(p, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    try {
                        ExtCert cert = CertKeyPersistence.loadCertPEMFromPath(file.toAbsolutePath());
                        certs.add(cert);
                    } catch (CertException | IOException e) {
                        log.debug("Unable to load certificate from " + file, e);
                    }
                    return super.visitFile(file, attrs);
                }
            });
        } catch (IOException ex) {
            log.debug("Unable to load certificate from path" + p.toAbsolutePath().toString(), ex);
        }
        return certs;
    }
}
