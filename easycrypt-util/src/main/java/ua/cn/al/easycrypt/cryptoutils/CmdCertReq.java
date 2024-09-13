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


import java.util.HashMap;
import java.util.Map;
import picocli.CommandLine.Command;

import picocli.CommandLine.Option;

/**
 *
 * @author alukin@gmail.com
 */

@Command(name="certreq", description = "Create, display, check certificate request")
public class CmdCertReq {

    @Option(names = {"--template", "-t"}, description = "Path to  file with default parameters")
    public String template="";
    @Option(names = {"--interactive", "-i"}, description = "Interactive mode")
    public Boolean interactive=false;
    @Option(names = {"--selfsigned", "-s"}, description = "Create self-signed X.509 certificate")
    public Boolean selfsigned=false;
    @Option(names = {"--rqtype", "-r"}, description = "Type of certificate request: personal, host, softsign") // validateWith = RqTypeValidator.class)
    public String rqtype="host";   
    @Option(names = {"--define","-D"}, description =  "Define property, e.g. certificate parameter. Format: name=value; May be used multiple times. Overwrites template")
    public Map<String, String> params = new HashMap<>();     
    @Option(names = {"--password", "-p"}, description = "Set challenge password in CSR")
    public String challengePassword="";
    @Option(names = {"--show", "-S"}, description = "Parse and show CSR")
    public boolean show;
}
