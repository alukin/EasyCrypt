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
