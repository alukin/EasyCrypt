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

package ua.cn.al.easycrypt.dataformat;

/**
 * Class that represents decryption result of AEADPlain (unencrypted part) and encrypted part of message
 * @author Oleksiy Lukin alukin@gmail.com
 * @author Serhiy Lymar serhiy.lymar@gmail.com 

 */
public class AEADPlain {
    /**
     * plain part of AEADPlain message
     */
    public byte[] plain;
    /**
     * decrypted part of AEADPlain message
     */
    public byte[] decrypted;
    /**
     * indicator of correctness
     */
    public boolean hmacOk;
}
