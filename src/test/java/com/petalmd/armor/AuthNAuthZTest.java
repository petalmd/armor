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

package com.petalmd.armor;

import java.util.Arrays;
import java.util.Collection;

import org.elasticsearch.common.settings.Settings;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import com.petalmd.armor.tests.DummyLoginModule;
import com.petalmd.armor.util.SecurityUtil;

@RunWith(Parameterized.class)
public class AuthNAuthZTest extends AbstractScenarioTest {

    @Parameter
    public boolean cacheEnabled;

    @Parameter(value = 1)
    public boolean wrongPwd;

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] { { true, true }, { false, false }, { false, true }, { true, false } });
    }

    @Test
    public void testLdapAuth() throws Exception {
        //Basic/Ldap/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.ldap.LDAPAuthenticationBackend")
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.username_attribute", "uid")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn").build();

        username = "jacksonm";
        password = "secret" + (wrongPwd ? "-wrong" : "");

        searchOnlyAllowed(settings, wrongPwd);
    }

    @Test
    public void testProxyAuth() throws Exception {
        //Proxy/Always/Ldap
        startLDAPServer();
        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.proxy.HTTPProxyAuthenticator")
                        .putArray("armor.authentication.proxy.trusted_ips", "*")
                        .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.username_attribute", "uid")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn").build();

        this.headers.put("X-Authenticated-User", "jacksonm" + (wrongPwd ? "-wrong" : ""));

        searchOnlyAllowed(settings, wrongPwd);
    }

    @Test
    public void testSpnegoAuth() throws Exception {
        //SPNEGO/Always/Ldap
        useSpnego = true;

        startLDAPServer();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final Settings settings = cacheEnabled(cacheEnabled)
                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.spnego.HTTPSpnegoAuthenticator")
                .put("armor.authentication.spnego.login_config_filepath", System.getProperty("java.security.auth.login.config"))
                .put("armor.authentication.spnego.krb5_config_filepath", System.getProperty("java.security.krb5.conf"))
                .put("armor.authentication.authorizer.impl", "com.petalmd.armor.authorization.ldap.LDAPAuthorizator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn").build();

        DummyLoginModule.username = "hnelson";
        DummyLoginModule.password = ("secret" + (wrongPwd ? "-wrong" : "")).toCharArray();

        searchOnlyAllowed(settings, wrongPwd);
    }

}
