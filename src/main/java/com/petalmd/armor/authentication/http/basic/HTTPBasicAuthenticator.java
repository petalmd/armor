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

package com.petalmd.armor.authentication.http.basic;

import java.nio.charset.StandardCharsets;

import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;

//TODO FUTURE allow only if protocol==https
public class HTTPBasicAuthenticator implements HTTPAuthenticator {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public HTTPBasicAuthenticator(final Settings settings) {
        this.settings = settings;
    }

    @Override
    public User authenticate(final RestRequest request, final RestChannel channel, final AuthenticationBackend backend,
            final Authorizator authorizator) throws AuthException {

        String authorizationHeader = request.header("Authorization");

        if (authorizationHeader != null) {

            if (!authorizationHeader.trim().toLowerCase().startsWith("basic ")) {
                throw new AuthException("Bad 'Authorization' header");
            } else {

                String decodedBasicHeader = new String(DatatypeConverter.parseBase64Binary(authorizationHeader.split(" ")[1]),
                        StandardCharsets.US_ASCII);

                final String[] decodedBasicHeaderParts = decodedBasicHeader.split(":");

                if (decodedBasicHeaderParts.length != 2 || decodedBasicHeaderParts[1] == null) {
                    log.warn("Invalid 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
                    askAgain(channel);
                    return null;
                } else {

                    final String username = decodedBasicHeaderParts[0];
                    char[] password = decodedBasicHeaderParts[1].toCharArray();

                    final User authenticatedUser = backend.authenticate(new AuthCredentials(username, password));

                    password = null;
                    decodedBasicHeader = null;
                    authorizationHeader = null;

                    authorizator.fillRoles(authenticatedUser, new AuthCredentials(authenticatedUser.getName(), null));

                    log.debug("User '{}' is authenticated", authenticatedUser);

                    return authenticatedUser;
                }
            }

        } else {
            log.trace("No 'Authorization' header, send 401 and 'WWW-Authenticate Basic'");
            askAgain(channel);
            return null;

        }
    }

    private void askAgain(final RestChannel channel) {
        final BytesRestResponse wwwAuthenticateResponse = new BytesRestResponse(RestStatus.UNAUTHORIZED);
        wwwAuthenticateResponse.addHeader("WWW-Authenticate", "Basic realm=\"Search Guard\"");
        channel.sendResponse(wwwAuthenticateResponse);
    }

}
