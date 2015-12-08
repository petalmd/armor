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

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.GuavaCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.petalmd.armor.authorization.GuavaCachingAuthorizator;
import com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

public class AuthCacheTest extends AbstractUnitTest {

    @Test
    public void testAuthentication() throws Exception {

        final Settings settings = Settings.settingsBuilder()
                .put("armor.authentication.settingsdb.user.spock", "vulcan")
                .put("armor.authentication.settingsdb.user.picard", "secret")
                .build();

        GuavaCachingAuthenticationBackend cache = new GuavaCachingAuthenticationBackend(new SettingsBasedAuthenticationBackend(settings), null);
        cache.authenticate((new AuthCredentials("spock", "vulcan".toCharArray())));
        cache.authenticate((new AuthCredentials("spock", "vulcan".toCharArray())));
        cache.authenticate((new AuthCredentials("spock", "vulcan".toCharArray())));
        cache.authenticate((new AuthCredentials("picard", "secret".toCharArray())));

        Assert.assertEquals(4, cache.getRequestCount());
        Assert.assertEquals(2, cache.getHitCount());
        Assert.assertEquals(2, cache.getMissCount());

    }

    @Test
    public void testAuthorization() throws Exception {

        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .build();

        GuavaCachingAuthorizator cache = new GuavaCachingAuthorizator(new SettingsBasedAuthorizator(settings), null);
        final User user = new User("spock");
        cache.fillRoles(user, null);
        cache.fillRoles(user, null);
        cache.fillRoles(user, null);
        cache.fillRoles(new User("spock"), null);
        cache.fillRoles(new User("dummy"), null);

        Assert.assertEquals(5, cache.getRequestCount());
        Assert.assertEquals(3, cache.getHitCount());
        Assert.assertEquals(2, cache.getMissCount());
        Assert.assertEquals(3, user.getRoles().size());

    }

    @Test
    public void testBoth() throws Exception {

        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.spock", "kolinahr", "starfleet", "command")
                .put("armor.authentication.settingsdb.user.spock", "vulcan")
                .put("armor.authentication.settingsdb.user.picard", "secret").build();


        GuavaCachingAuthenticationBackend authCache = new GuavaCachingAuthenticationBackend(new SettingsBasedAuthenticationBackend(settings), null);
        AuthCredentials ac = new AuthCredentials("spock", "vulcan".toCharArray());
        authCache.authenticate(ac);
        authCache.authenticate(ac);
        User user = authCache.authenticate(ac);
        authCache.authenticate((new AuthCredentials("picard", "secret".toCharArray())));

        Assert.assertEquals(4, authCache.getRequestCount());
        Assert.assertEquals(2, authCache.getHitCount());
        Assert.assertEquals(2, authCache.getMissCount());

        GuavaCachingAuthorizator cache = new GuavaCachingAuthorizator(new SettingsBasedAuthorizator(settings), null);
        cache.fillRoles(user, null);
        cache.fillRoles(user, null);
        cache.fillRoles(user, null);
        cache.fillRoles(new User("spock"), null);
        cache.fillRoles(new User("dummy"), null);

        Assert.assertEquals(5, cache.getRequestCount());
        Assert.assertEquals(3, cache.getHitCount());
        Assert.assertEquals(2, cache.getMissCount());
        Assert.assertEquals(3, user.getRoles().size());
    }
}
