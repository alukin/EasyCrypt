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
package ua.cn.al.easycrypt.container;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Data record for Wallet
 * @author Oleksiy Lukin alukin@gmail.com
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DataRecord {
    public String alias;
    public String encoding;
    public String description;
    public String data;
    public long timestamp;
}
