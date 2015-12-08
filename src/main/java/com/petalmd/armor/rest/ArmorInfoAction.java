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

package com.petalmd.armor.rest;

import com.petalmd.armor.ArmorPlugin;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.rest.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.elasticsearch.rest.RestRequest.Method.GET;

public class ArmorInfoAction extends BaseRestHandler {

    private final ArmorService service;

    @Inject
    public ArmorInfoAction(final Settings settings, final RestController controller, final Client client,
                           final ArmorService service) {
        super(settings, controller, client);
        controller.registerHandler(GET, "/_searchguard", this);
        this.service = service;
    }

    @Override
    protected void handleRequest(final RestRequest request, final RestChannel channel, final Client client) throws Exception {
        final boolean isLoopback = ((InetSocketAddress) request.getRemoteAddress()).getAddress().isLoopbackAddress();
        final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

        final Authorizator authorizator = service.getAuthorizator();
        final AuthenticationBackend authenticationBackend = service.getAuthenticationBackend();
        final HTTPAuthenticator httpAuthenticator = service.getHttpAuthenticator();

        BytesRestResponse response = null;
        final XContentBuilder builder = channel.newBuilder();

        try {

            final User authenticatedUser = httpAuthenticator.authenticate(request, channel, authenticationBackend, authorizator);

            if (authenticatedUser == null) {
                return;
            }

            builder.startObject();

            builder.field("armor.status", "running");
            builder.field("armor.dls.supported", ArmorPlugin.DLS_SUPPORTED);
            builder.field("armor.fls.supported", ArmorPlugin.DLS_SUPPORTED);
            builder.field("armor.isloopback", isLoopback);
            builder.field("armor.resolvedaddress", resolvedAddress);
            builder.field("armor.authenticated_user", authenticatedUser.getName());

            builder.field("armor.roles", authenticatedUser, authenticatedUser.getRoles());

            builder.endObject();

            response = new BytesRestResponse(RestStatus.OK, builder);
        } catch (final Exception e1) {
            builder.startObject();
            builder.field("error", e1.toString());
            builder.endObject();
            response = new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, builder);
        }

        channel.sendResponse(response);

    }

}
