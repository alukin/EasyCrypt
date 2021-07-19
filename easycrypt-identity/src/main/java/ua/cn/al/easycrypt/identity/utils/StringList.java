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

package ua.cn.al.easycrypt.identity.utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Semicolon separated list of strings
 * @author alukin@gmail.com
 */
public class StringList {
    public static String fromList(List<String> sl) {
        String res = "";
        for (int i = 0; i < sl.size(); i++) {
            String semicolon = i < sl.size() - 1 ? ";" : "";
            res += sl.get(i) + semicolon;
        }
        return res;
    }

    public static List<String> fromString(String l) {
        List<String> res = new ArrayList<>();
        String[] ll = l.split(";");
        for (String s : ll) {
            if (!s.isEmpty()) {
                res.add(s);
            }
        }
        return res;
    }    
}
