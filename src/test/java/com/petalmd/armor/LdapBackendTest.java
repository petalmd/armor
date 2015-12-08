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

import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.LdapUser;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.ldap.LDAPAuthenticationBackend;
import com.petalmd.armor.authorization.GuavaCachingAuthorizator;
import com.petalmd.armor.authorization.ldap.LDAPAuthorizator;
import com.petalmd.armor.util.SecurityUtil;

public class LdapBackendTest extends AbstractUnitTest {

    @Test
    public void testLdapAuthentication() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "123.xxx.1:838b9", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})").build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationUserNameAttribute() throws Exception {

        startLDAPServer();

        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "123.xxx.1:838b9", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.username_attribute", "uid")

                .build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("jacksonm", user.getName());
    }

    @Test
    public void testLdapAuthenticationSSL() throws Exception {

        startLDAPServer();

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.ldaps.ssl.enabled", "true")
                .put("armor.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("armor.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationSSLWrongPwd() throws Exception {

        startLDAPServer();

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.ldaps.ssl.enabled", "true")
                .put("armor.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("armor.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm",
                "secret-wrong".toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthenticationStartTLS() throws Exception {

        startLDAPServer();

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.ldaps.ssl.enabled", "false")
                .put("armor.authentication.ldap.ldaps.starttls.enabled", "true")
                .put("armor.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationSSLPlainFail() throws Exception {

        startLDAPServer();

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapsServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.ldap.ldaps.ssl.enabled", "false")
                .put("armor.authentication.ldap.ldaps.starttls.enabled", "false")

                .put("armor.authentication.ldap.ldaps.truststore_filepath",
                        SecurityUtil.getAbsoluteFilePathFromClassPath("SearchguardTS.jks")).build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret"
                .toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthenticationFail() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})").build();

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));

        final LdapUser user = (LdapUser) new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm",
                "secret-wrong".toCharArray()));
        Assert.assertNotNull(user);
        Assert.assertEquals("cn=Michael Jackson,ou=people,o=TEST", user.getName());
    }

    @Test
    public void testLdapAuthorizationDN() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());
    }

    @Test(expected = AuthException.class)
    public void testLdapAuthorizationDNWithNonAnonBindFail() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.ldap.bind_dn", "xxx").put("armor.authentication.ldap.password", "ccc").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationDNWithNonAnonBind() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.ldap.bind_dn", "cn=Captain Spock,ou=people,o=TEST")
                .put("armor.authentication.ldap.password", "spocksecret").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final User user = new LDAPAuthenticationBackend(settings).authenticate(new AuthCredentials("jacksonm", "secret".toCharArray()));
        Assert.assertTrue(user instanceof LdapUser);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials(user.getName(), null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, ((LdapUser) user).getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorization() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("jacksonm", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("jacksonm", null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, user.getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationUserRoles() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.userrolename", "description").build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("jacksonm", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("jacksonm", null));
        Assert.assertEquals(3, user.getRoles().size());
        Assert.assertEquals(3, user.getRoleEntries().size());

    }

    @Test
    public void testLdapAuthorizationNestedRoles() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.resolve_nested_roles", true)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("spock", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals(4, user.getRoleEntries().size());
    }

    @Test
    public void testLdapAuthorizationNestedRolesCache() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.resolve_nested_roles", true)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        LdapUser user = new LdapUser("spock", null);
        final GuavaCachingAuthorizator gc = new GuavaCachingAuthorizator(new LDAPAuthorizator(settings), settings);
        gc.fillRoles(user, new AuthCredentials("spock", null));
        user = new LdapUser("spock", null);
        gc.fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(4, user.getRoles().size());
        Assert.assertEquals(4, user.getRoleEntries().size());
    }

    @Test
    public void testLdapAuthorizationNestedRolesOff() throws Exception {
        startLDAPServer();
        final Settings settings = Settings.settingsBuilder()
                .putArray("armor.authentication.ldap.host", "localhost:" + ldapServerPort)
                .put("armor.authentication.ldap.usersearch", "(uid={0})")
                .put("armor.authentication.authorization.ldap.rolename", "cn")
                .put("armor.authentication.authorization.ldap.rolesearch", "(uniqueMember={0})")
                .put("armor.authentication.authorization.ldap.resolve_nested_roles", false)

                .build();
        //userrolename

        //Role names may also be held as the values of an attribute in the user's directory entry. Use userRoleName to specify the name of this attribute.

        ldapServer.applyLdif(SecurityUtil.getAbsoluteFilePathFromClassPath("ldif1.ldif"));
        final LdapUser user = new LdapUser("spock", null);
        new LDAPAuthorizator(settings).fillRoles(user, new AuthCredentials("spock", null));
        Assert.assertEquals(2, user.getRoles().size());
        Assert.assertEquals(2, user.getRoleEntries().size());

    }
}
