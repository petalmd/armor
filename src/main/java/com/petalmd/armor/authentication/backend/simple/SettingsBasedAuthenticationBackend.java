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

package com.petalmd.armor.authentication.backend.simple;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang.StringUtils;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.util.ConfigConstants;

public class SettingsBasedAuthenticationBackend implements NonCachingAuthenticationBackend {

    private final Settings settings;

    @Inject
    public SettingsBasedAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final com.petalmd.armor.authentication.AuthCredentials authCreds) throws AuthException {
        final String user = authCreds.getUsername();
        final String clearTextPassword = authCreds.getPassword() == null?null:new String(authCreds.getPassword());
        authCreds.clear();

        String digest = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_DIGEST, null);
        final String storedPasswordOrDigest = settings.get(ConfigConstants.ARMOR_AUTHENTICATION_SETTINGSDB_USER + user, null);

        if(!StringUtils.isEmpty(clearTextPassword) && !StringUtils.isEmpty(storedPasswordOrDigest)) {

            String passwordOrHash = clearTextPassword;

            if (digest != null) {

                digest = digest.toLowerCase();

                switch (digest) {

                    case "sha":
                    case "sha1":
                        passwordOrHash = DigestUtils.sha1Hex(clearTextPassword);
                        break;
                    case "sha256":
                        passwordOrHash = DigestUtils.sha256Hex(clearTextPassword);
                        break;
                    case "sha384":
                        passwordOrHash = DigestUtils.sha384Hex(clearTextPassword);
                        break;
                    case "sha512":
                        passwordOrHash = DigestUtils.sha512Hex(clearTextPassword);
                        break;

                    default:
                        passwordOrHash = DigestUtils.md5Hex(clearTextPassword);
                        break;
                }

            }

            if (storedPasswordOrDigest.equals(passwordOrHash)) {
                return new User(user);
            }

        }

        throw new AuthException("No user " + user + " or wrong password (digest: " + (digest == null ? "plain/none" : digest) + ")");
    }
}
