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

package com.petalmd.armor.util;

public final class ConfigConstants {

    public static final String DEFAULT_SECURITY_CONFIG_INDEX = "armor";
    public static final String ARMOR_ACTIONREQUESTFILTER = "armor.actionrequestfilter.names";
    public static final String ARMOR_ALLOW_ALL_FROM_LOOPBACK = "armor.allow_all_from_loopback";
    public static final String ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX = "armor.allow_non_loopback_query_on_armor_index";
    public static final String ARMOR_ALLOW_KIBANA_ACTIONS = "armor.allow_kibana_actions";
    public static final String ARMOR_AUDITLOG_ENABLED = "armor.auditlog.enabled";
    public static final String ARMOR_TRANSPORT_AUTH_ENABLED = "armor.transport_auth.enabled";
    public static final String ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND = "armor.authentication.authentication_backend.impl";
    public static final String ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE = "armor.authentication.authentication_backend.cache.enable";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_RESOLVE_NESTED_ROLES = "armor.authentication.authorization.ldap.resolve_nested_roles";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLEBASE = "armor.authentication.authorization.ldap.rolebase";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLENAME = "armor.authentication.authorization.ldap.rolename";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_ROLESEARCH = "armor.authentication.authorization.ldap.rolesearch";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLEATTRIBUTE = "armor.authentication.authorization.ldap.userroleattribute";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_LDAP_USERROLENAME = "armor.authentication.authorization.ldap.userrolename";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZATION_SETTINGSDB_ROLES = "armor.authentication.authorization.settingsdb.roles.";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZER = "armor.authentication.authorizer.impl";
    public static final String ARMOR_AUTHENTICATION_AUTHORIZER_CACHE_ENABLE = "armor.authentication.authorizer.cache.enable";
    public static final String ARMOR_AUTHENTICATION_HTTP_AUTHENTICATOR = "armor.authentication.http_authenticator.impl";
    public static final String ARMOR_AUTHENTICATION_HTTPS_CLIENTCERT_ATTRIBUTENAME = "armor.authentication.https.clientcert.attributename";
    public static final String ARMOR_AUTHENTICATION_LDAP_BIND_DN = "armor.authentication.ldap.bind_dn";
    public static final String ARMOR_AUTHENTICATION_LDAP_HOST = "armor.authentication.ldap.host";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_SSL_ENABLED = "armor.authentication.ldap.ldaps.ssl.enabled";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_STARTTLS_ENABLED = "armor.authentication.ldap.ldaps.starttls.enabled";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_FILEPATH = "armor.authentication.ldap.ldaps.truststore_filepath";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_PASSWORD = "armor.authentication.ldap.ldaps.truststore_password";
    public static final String ARMOR_AUTHENTICATION_LDAP_LDAPS_TRUSTSTORE_TYPE = "armor.authentication.ldap.ldaps.truststore_type";
    public static final String ARMOR_AUTHENTICATION_LDAP_PASSWORD = "armor.authentication.ldap.password";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERBASE = "armor.authentication.ldap.userbase";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE = "armor.authentication.ldap.username_attribute";
    public static final String ARMOR_AUTHENTICATION_LDAP_USERSEARCH = "armor.authentication.ldap.usersearch";
    public static final String ARMOR_AUTHENTICATION_PROXY_HEADER = "armor.authentication.proxy.header";
    public static final String ARMOR_AUTHENTICATION_PROXY_TRUSTED_IPS = "armor.authentication.proxy.trusted_ips";
    public static final String ARMOR_AUTHENTICATION_SETTINGSDB_DIGEST = "armor.authentication.settingsdb.digest";
    public static final String ARMOR_AUTHENTICATION_SETTINGSDB_USER = "armor.authentication.settingsdb.user.";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_KRB5_CONFIG_FILEPATH = "armor.authentication.spnego.krb5_config_filepath";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_FILEPATH = "armor.authentication.spnego.login_config_filepath";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_LOGIN_CONFIG_NAME = "armor.authentication.spnego.login_config_name";
    public static final String ARMOR_AUTHENTICATION_SPNEGO_STRIP_REALM = "armor.authentication.spnego.strip_realm";
    public static final String ARMOR_AUTHENTICATION_WAFFLE_STRIP_DOMAIN = "armor.authentication.waffle.strip_domain";
    public static final String ARMOR_CHECK_FOR_ROOT = "armor.check_for_root";
    public static final String ARMOR_CONFIG_INDEX_NAME = "armor.config_index_name";
    public static final String ARMOR_DLSFILTER = "armor.dlsfilter.names";
    public static final String ARMOR_ENABLED = "armor.enabled";
    public static final String ARMOR_FLSFILTER = "armor.flsfilter.names";
    public static final String ARMOR_HTTP_ENABLE_SESSIONS = "armor.http.enable_sessions";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_ENFORCE = "armor.http.xforwardedfor.enforce";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_HEADER = "armor.http.xforwardedfor.header";
    public static final String ARMOR_HTTP_XFORWARDEDFOR_TRUSTEDPROXIES = "armor.http.xforwardedfor.trustedproxies";
    public static final String ARMOR_KEY_PATH = "armor.key_path";
    public static final String ARMOR_RESTACTIONFILTER = "armor.restactionfilter.names";
    public static final String ARMOR_REWRITE_GET_AS_SEARCH = "armor.rewrite_get_as_search";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_ENABLED = "armor.ssl.transport.http.enabled";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_ENFORCE_CLIENTAUTH = "armor.ssl.transport.http.enforce_clientauth";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_FILEPATH = "armor.ssl.transport.http.keystore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_PASSWORD = "armor.ssl.transport.http.keystore_password";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_KEYSTORE_TYPE = "armor.ssl.transport.http.keystore_type";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_FILEPATH = "armor.ssl.transport.http.truststore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_PASSWORD = "armor.ssl.transport.http.truststore_password";
    public static final String ARMOR_SSL_TRANSPORT_HTTP_TRUSTSTORE_TYPE = "armor.ssl.transport.http.truststore_type";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENABLED = "armor.ssl.transport.node.enabled";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION = "armor.ssl.transport.node.encforce_hostname_verification";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION_RESOLVE_HOST_NAME = "armor.ssl.transport.node.encforce_hostname_verification.resolve_host_name";
    public static final String ARMOR_SSL_TRANSPORT_NODE_ENFORCE_CLIENTAUTH = "armor.ssl.transport.node.enforce_clientauth";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH = "armor.ssl.transport.node.keystore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_PASSWORD = "armor.ssl.transport.node.keystore_password";
    public static final String ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_TYPE = "armor.ssl.transport.node.keystore_type";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH = "armor.ssl.transport.node.truststore_filepath";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_PASSWORD = "armor.ssl.transport.node.truststore_password";
    public static final String ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_TYPE = "armor.ssl.transport.node.truststore_type";
    public static final String ARMOR_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL = "armor.waffle.windows_auth_provider_impl";

    private ConfigConstants() {

    }

}
