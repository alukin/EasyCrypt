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
package ua.cn.al.easycrypt;

/**
 * Universal exception that indicates problems with keys or data
 *
 * @author Oleksiy Lukin alukin@gmail.com
 */
public final class CryptoNotValidException extends Exception {

    public CryptoNotValidException(String message) {
        super(message);
    }

    public CryptoNotValidException(String message, Throwable cause) {
        super(message, cause);
    }

}
