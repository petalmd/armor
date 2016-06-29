/*
 * Copyright 2015 PetalMD
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.petalmd.armor;

import org.elasticsearch.common.inject.CreationException;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.petalmd.armor.util.SecurityUtil;

public class UnixTest extends AbstractScenarioTest {

    @Test(expected = CreationException.class)
    public void testWaffleFailOnUnix() throws Exception {

        final Settings settings = Settings
                .settingsBuilder()
                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.waffle.HTTPWaffleAuthenticator")
                        .put("armor.authentication.authorizer", "com.petalmd.armor.authorization.waffle.WaffleAuthorizator")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend").build();

        username = "Guest";
        password = "Guest";

        searchOnlyAllowed(settings, true);
    }

    @Test
    public void isRootTest() throws Exception {
        Assert.assertFalse(SecurityUtil.isRootUser());
    }

}
