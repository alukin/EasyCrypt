/*
 * Copyright (C) 2018-2021 Oleksiy Lukin <alukin@gmail.com> and CONTRIBUTORS
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

package ua.cn.al.easycrypt.cryptoutils;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 *
 * @author alukin@gmail.com
 */
@Command(name="x509", description = "Display, check X.509 certificate, sign PKCS#10 CSR")
public class CmdX509Cert {
    @Option(names = {"--show", "-S"}, description = "Parse and show X.509 certificate")
    public boolean show;
    @Option(names = {"--signby"}, description = "SIGN PKCS#10 CSR by given CA X.509 certificate")
    public String signby;
}
