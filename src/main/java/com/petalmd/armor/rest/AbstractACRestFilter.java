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

import com.google.common.collect.Lists;
import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authentication.http.HTTPAuthenticator;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.http.Session;
import com.petalmd.armor.http.SessionStore;
import com.petalmd.armor.http.netty.SessionAwareNettyHttpChannel;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.http.netty.NettyHttpServerTransport;
import org.elasticsearch.index.query.IdsQueryBuilder;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.action.support.RestActions;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.search.fetch.source.FetchSourceContext;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public abstract class AbstractACRestFilter extends RestFilter {

    public static final String REST_ACTION_MULTI_ALLOW_EXPLICIT_INDEX = "rest.action.multi.allow_explicit_index";

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final ArmorService service;
    protected final Settings settings;
    protected final AuditListener auditListener;
    protected final String filterType;
    protected final String filterName;
    protected final boolean rewriteGetAsSearch;
    protected final Authorizator authorizator;
    protected final AuthenticationBackend authenticationBackend;
    protected final HTTPAuthenticator httpAuthenticator;
    protected final SessionStore sessionStore;
    protected final boolean allowAllFromLoopback;

    public AbstractACRestFilter(final ArmorService service, final String filterType, final String filterName,
            final AuditListener auditListener) {

        this.service = service;
        this.filterName = filterName;
        this.filterType = filterType;
        this.settings = service.getSettings();
        this.auditListener = auditListener;
        this.rewriteGetAsSearch = settings.getAsBoolean(ConfigConstants.ARMOR_REWRITE_GET_AS_SEARCH, true);

        this.authenticationBackend = service.getAuthenticationBackend();
        this.httpAuthenticator = service.getHttpAuthenticator();
        this.authorizator = service.getAuthorizator();
        this.sessionStore = service.getSessionStore();
        allowAllFromLoopback = settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_ALL_FROM_LOOPBACK, false);

    }

    @Override
    public final void process(final RestRequest request, final RestChannel origRestChannel, final RestFilterChain filterChain)
            throws Exception {

        final boolean isLoopback = allowAllFromLoopback
                && ((InetSocketAddress) request.getRemoteAddress()).getAddress().isLoopbackAddress();

        log.debug("--> Rest request {}/{} {} {} (loopback?: {})", filterType, filterName, request.method(), request.path(), isLoopback);
        log.trace("Context: {}", request.getContext());

        //allow all if request is coming from loopback
        if (isLoopback) {
            log.debug("This is a connection from localhost/loopback, will allow all");
            filterChain.continueProcessing(request, origRestChannel);
            return;
        }

        if (request.method() == Method.OPTIONS) {
            log.debug("This is a OPTIONS request, will allow");
            filterChain.continueProcessing(request, origRestChannel);
            return;
        }

        RestChannel channel = origRestChannel;

        if (settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false)) {
            channel = new SessionAwareNettyHttpChannel(origRestChannel, sessionStore, settings.getAsBoolean(
                    NettyHttpServerTransport.SETTING_HTTP_DETAILED_ERRORS_ENABLED, true));
        }

        if (request.hasInContext("armor_filter") && filterType != null) {
            if (!((List<String>) request.getFromContext("armor_filter")).contains(filterType + ":" + filterName)) {
                ((List<String>) request.getFromContext("armor_filter")).add(filterType + ":" + filterName);
            }
        } else if (filterType != null) {
            final List<String> filters = new ArrayList<String>();
            filters.add(filterType + ":" + filterName);
            request.putInContext("armor_filter", filters);
        }

        //this is needed because of a authentication attempt with kerberos could be identified as a reply
        if (request.hasInContext("armor_authenticated_user")) {
            log.trace("Already processed, execute directly");
            processSecure(request, origRestChannel, filterChain);
            return;
        }

        log.debug("execute filter {}", filterName == null ? "DEFAULT" : filterName);
        log.trace("Path: {} {}", request.method(), request.path());

        log.trace("Headers: {}", Lists.newArrayList(request.headers()));
        try {
            log.trace("Source: {}", request.content() == null ? "null" : request.content().toUtf8());
        } catch (final Exception e) {
            log.trace("Source: {}", request.content() == null ? "null" : new String(request.content().array()));
        }

        final InetAddress resolvedAddress = SecurityUtil.getProxyResolvedHostAddressFromRequest(request, settings);

        log.debug("This is a connection from {}", resolvedAddress.getHostAddress());

        User sessionUser = null;

        if (settings.getAsBoolean(ConfigConstants.ARMOR_HTTP_ENABLE_SESSIONS, false)) {

            final String sessionId = SecurityUtil.getSearchGuardSessionIdFromCookie(request);

            if (sessionId == null) {
                log.debug("No cookie found, will call authenticator");
            } else {
                final Session session = sessionStore.getSession(sessionId);
                if (session != null) {
                    sessionUser = session.getAuthenticatedUser();
                    log.debug("Found a session {}", session);
                } else {
                    log.warn("Found search guard cookie but with invalid id, will call authenticator");
                }
            }

        }

        try {

            if (sessionUser == null) {
                sessionUser = httpAuthenticator.authenticate(request, channel, authenticationBackend, authorizator);

                if (sessionUser == null) {
                    log.trace("Authentication not finished");
                    return;
                } else {
                    log.trace("Authentication finished");
                }

            } else {
                log.debug("User already authenticated earlier in the session");
            }

            final User authenticatedUser = sessionUser;

            log.info("Authenticated user is {}", authenticatedUser);

            request.putInContext("armor_authenticated_user", authenticatedUser);
            request.putInContext("armor_resolved_rest_address", resolvedAddress);

            processSecure(request, channel, filterChain);
            return;

        } catch (final AuthException e1) {
            auditListener.onFailedLogin("unknown", request);
            log.error(e1.toString(), e1);
            throw e1;
        } catch (final Exception e1) {
            log.error(e1.toString(), e1);
            throw e1;
        }

    }

    public abstract void processSecure(RestRequest request, RestChannel channel, RestFilterChain filterChain) throws Exception;

    protected SearchRequest toSearchRequest(final RestRequest request) {

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.routing(request.param("routing"));
        searchRequest.copyContextFrom(request);
        searchRequest.preference(request.param("preference"));
        searchRequest.indices(request.param("index"));
        searchRequest.types(request.param("type"));
        searchRequest.source(SearchSourceBuilder.searchSource().query(
                new IdsQueryBuilder(request.param("type")).addIds(request.param("id"))));
        return searchRequest;

    }

    protected MultiSearchRequest toMultiSearchRequest(final RestRequest request) throws Exception {

        final MultiGetRequest multiGetRequest = new MultiGetRequest();
        multiGetRequest.refresh(request.paramAsBoolean("refresh", multiGetRequest.refresh()));
        multiGetRequest.preference(request.param("preference"));
        multiGetRequest.realtime(request.paramAsBoolean("realtime", null));
        multiGetRequest.ignoreErrorsOnGeneratedFields(request.paramAsBoolean("ignore_errors_on_generated_fields", false));

        String[] sFields = null;
        final String sField = request.param("fields");
        if (sField != null) {
            sFields = Strings.splitStringByCommaToArray(sField);
        }

        final FetchSourceContext defaultFetchSource = FetchSourceContext.parseFromRestRequest(request);
        multiGetRequest.add(request.param("index"), request.param("type"), sFields, defaultFetchSource, request.param("routing"),
                RestActions.getRestContent(request),
                settings.getAsBoolean(AbstractACRestFilter.REST_ACTION_MULTI_ALLOW_EXPLICIT_INDEX, true));

        final MultiSearchRequest msearch = new MultiSearchRequest();
        msearch.copyContextFrom(request);

        for (final Iterator<Item> iterator = multiGetRequest.iterator(); iterator.hasNext();) {
            final Item item = iterator.next();

            final SearchRequest st = new SearchRequest();
            st.routing(item.routing());
            st.indices(item.indices());
            st.types(item.type());
            st.preference(request.param("preference"));
            st.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder(item.type()).addIds(item.id())));
            msearch.add(st);
        }

        return msearch;

    }

}
