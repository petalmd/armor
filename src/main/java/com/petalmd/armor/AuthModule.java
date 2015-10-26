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

import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.settings.Settings;

import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.audit.ESStoreAuditListener;
import com.petalmd.armor.audit.NullStoreAuditListener;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.backend.GuavaCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.NonCachingAuthenticationBackend;
import com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authentication.http.basic.HTTPBasicAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.GuavaCachingAuthorizator;
import com.petalmd.armor.authorization.NonCachingAuthorizator;
import com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator;
import com.petalmd.armor.http.DefaultSessionStore;
import com.petalmd.armor.http.NullSessionStore;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;

public final class AuthModule extends AbstractModule {

    private final Settings settings;

    public AuthModule(final Settings settings) {
        this.settings = settings;
    }

    @Override
    protected void configure() {

        final Class<? extends NonCachingAuthenticationBackend> defaultNonCachingAuthenticationBackend = SettingsBasedAuthenticationBackend.class;
        final Class<? extends HTTPAuthenticator> defaultHTTPAuthenticator = HTTPBasicAuthenticator.class;
        final Class<? extends NonCachingAuthorizator> defaultNonCachingAuthorizator = SettingsBasedAuthorizator.class;

        final Class<? extends NonCachingAuthenticationBackend> authenticationBackend = settings.getAsClass(
                ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND, defaultNonCachingAuthenticationBackend);

        final Class<? extends HTTPAuthenticator> httpAuthenticator = settings.getAsClass(
                ConfigConstants.ARMOR_AUTHENTICATION_HTTP_AUTHENTICATOR, defaultHTTPAuthenticator);
        bind(HTTPAuthenticator.class).to(httpAuthenticator).asEagerSingleton();

        final Class<? extends NonCachingAuthorizator> authorizator = settings.getAsClass(
                ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZER, defaultNonCachingAuthorizator);

        if (settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_AUTHENTICATION_BACKEND_CACHE_ENABLE, true)) {
            bind(NonCachingAuthenticationBackend.class).to(authenticationBackend).asEagerSingleton();
            bind(AuthenticationBackend.class).to(GuavaCachingAuthenticationBackend.class).asEagerSingleton();
        } else {
            bind(AuthenticationBackend.class).to(authenticationBackend).asEagerSingleton();
        }

        if (settings.getAsBoolean(ConfigConstants.ARMOR_AUTHENTICATION_AUTHORIZER_CACHE_ENABLE, true)) {
            bind(NonCachingAuthorizator.class).to(authorizator).asEagerSingleton();
            bind(Authorizator.class).to(GuavaCachingAuthorizator.class).asEagerSingleton();
        } else {
            bind(Authorizator.class).to(authorizator).asEagerSingleton();
        }

        if (settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false)) {
            bind(SessionStore.class).to(DefaultSessionStore.class).asEagerSingleton();
        } else {
            bind(SessionStore.class).to(NullSessionStore.class).asEagerSingleton();
        }

        bind(IWindowsAuthProvider.class).to(
                settings.getAsClass(ConfigConstants.ARMOR_WAFFLE_WINDOWS_AUTH_PROVIDER_IMPL, WindowsAuthProviderImpl.class))
                .asEagerSingleton();

        bind(AuditListener.class).to(
                settings.getAsBoolean(ConfigConstants.ARMOR_AUDITLOG_ENABLED, true) ? ESStoreAuditListener.class
                        : NullStoreAuditListener.class).asEagerSingleton();

        bind(ArmorService.class).asEagerSingleton();

        bind(ArmorConfigService.class).asEagerSingleton();
    }

}
