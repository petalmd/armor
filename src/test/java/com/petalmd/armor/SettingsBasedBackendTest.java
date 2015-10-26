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

import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator;

public class SettingsBasedBackendTest extends AbstractUnitTest {

    @Test
    public void testSimple() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "vulcan").build();

        Assert.assertEquals("spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "vulcan".toCharArray()))
                .getName());

    }

    @Test
    public void testSimpleRoles() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "vulcan").build();

        Assert.assertEquals("spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "vulcan".toCharArray()))
                .getName());

        final User user = new User("spock");
        final Authorizator authorizator = new SettingsBasedAuthorizator(settings);
        authorizator.fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(3, user.getRoles().size());

    }

    @Test
    public void testDigestMd5() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "0c94ea3ecdd57ac44984589682e4be05")
                .put("armor.authentication.settingsdb.digest", "md5").build();

        Assert.assertEquals(
                "spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(
                        new AuthCredentials("spock", "vulcan".toCharArray())).getName());

    }

    @Test
    public void testDigestSha1() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "966032eab6276624119a49080934e3936d2976f7")
                .put("armor.authentication.settingsdb.digest", "sha1").build();

        Assert.assertEquals(
                "spock",
                new SettingsBasedAuthenticationBackend(settings).authenticate(
                        new AuthCredentials("spock", "vulcan".toCharArray())).getName());

    }

    @Test(expected = AuthException.class)
    public void testDigestSha1Fail() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "966032eab6276624119a49080934e3936d2976f7")
                .put("armor.authentication.settingsdb.digest", "sha1").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "wrong-password".toCharArray()));

    }

    @Test(expected = AuthException.class)
    public void testDigestSha1FailDigestAgain() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
            .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
            .put("searchguard.authentication.settingsdb.user.spock", "966032eab6276624119a49080934e3936d2976f7")
            .put("searchguard.authentication.settingsdb.digest", "sha1").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "966032eab6276624119a49080934e3936d2976f7".toCharArray()));
    }


    @Test(expected = AuthException.class)
    public void testFailUser() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "vulcan").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("picard", "secret".toCharArray()));

    }

    @Test(expected = AuthException.class)
    public void testFailPassword() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "vulcan").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "secret".toCharArray()));

    }

    @Test(expected = AuthException.class)
    public void testFailNullPassword() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", null));

    }

    @Test(expected = AuthException.class)
    public void testFailEmptyPassword() throws Exception {

        final Settings settings = ImmutableSettings.settingsBuilder()
                .putArray("searchguard.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("searchguard.authentication.settingsdb.user.spock", "").build();

        new SettingsBasedAuthenticationBackend(settings).authenticate(new AuthCredentials("spock", "".toCharArray()));

    }
}
