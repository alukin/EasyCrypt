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


import picocli.CommandLine.ParameterException;

/**
 * @author Oleksiy Lukin alukin@gmail.com
 */
public class RqTypeValidator { // implements IParameterValidator {
    
    public static final String[] RQ_TYPES = {"personal", "host", "softsign"};


    public void validate(String name, String value) throws ParameterException {
        boolean found = false;
        for (String p : RQ_TYPES) {
            if (p.equalsIgnoreCase(value)) {
                found = true;
                break;
            }
        }
        if (!found) {
            // throw new ParameterException( "Parameter " + name + " should be one of:" + Arrays.toString(RQ_TYPES) + " (found " + value + ")");
        }
    }
    
}
