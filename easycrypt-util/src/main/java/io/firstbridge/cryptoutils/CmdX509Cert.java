/*
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

package io.firstbridge.cryptoutils;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

/**
 *
 * @author alukin@gmail.com
 */
@Parameters(commandDescription = "Display, check X.509 certificate, sign PKCS#10 CSR")
public class CmdX509Cert {
    @Parameter(names = {"--show", "-S"}, description = "Parse and show X.509 certificate")
    public boolean show;
    @Parameter(names = {"--signby"}, description = "SIGN PKCS#10 CSR by given CA X.509 certificate")
    public String signby;
}
