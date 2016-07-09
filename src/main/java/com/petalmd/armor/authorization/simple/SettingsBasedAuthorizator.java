/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

package com.petalmd.armor.authorization.simple;

import java.util.Arrays;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authorization.NonCachingAuthorizator;
import com.petalmd.armor.util.ConfigConstants;

public class SettingsBasedAuthorizator implements NonCachingAuthorizator {

    private final Settings settings;

    @Inject
    public SettingsBasedAuthorizator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public void fillRoles(final User user, final AuthCredentials optionalAuthCreds) throws AuthException {

        final String[] roles = settings.getAsArray(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES
                + user.getName());

        if (optionalAuthCreds != null) {
            optionalAuthCreds.clear();
        }

        if (roles != null) {
            user.addRoles(Arrays.asList(roles));
        }
    }
}
