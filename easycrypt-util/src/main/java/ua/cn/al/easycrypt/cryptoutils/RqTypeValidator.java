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
