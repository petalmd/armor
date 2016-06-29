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
package com.petalmd.armor.filter;

import com.petalmd.armor.audit.AuditListener;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import javax.xml.bind.DatatypeConverter;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.get.MultiGetRequest.Item;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.MultiSearchResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.DelegatingActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.get.GetResult;
import org.elasticsearch.index.query.IdsQueryBuilder;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;

import com.petalmd.armor.authentication.AuthCredentials;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.MalformedConfigurationException;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportRequest;

public abstract class AbstractActionFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    protected final Settings settings;
    protected final AuthenticationBackend backend;
    protected final AuditListener auditListener;
    protected final Authorizator authorizator;
    protected final ClusterService clusterService;
    protected final ArmorConfigService armorConfigService;

    @Override
    public final int order() {
        return Integer.MIN_VALUE;
    }

    protected AbstractActionFilter(final Settings settings, final AuthenticationBackend backend, final Authorizator authorizator,
            final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        this.settings = settings;
        this.authorizator = authorizator;
        this.backend = backend;
        this.clusterService = clusterService;
        this.armorConfigService = armorConfigService;
        this.auditListener = auditListener;
    }

    @Override
    public final void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {
        log.debug("REQUEST on node {}: {} ({}) from {}", clusterService.localNode().getName(), action, request.getClass(),
                request.remoteAddress() == null ? "INTRANODE" : request.remoteAddress().toString());
        log.debug("Context {}", request.getContext());
        log.debug("Headers {}", request.getHeaders());

        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true) && (action.startsWith("cluster:monitor/") || action.contains("indices:data/read/field_stats"))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final User restUser = request.getFromContext("armor_authenticated_user", null);

        final boolean restAuthenticated = restUser != null;

        if (restAuthenticated) {
            log.debug("TYPE: rest authenticated request, apply filters");
            applySecure(task, action, request, listener, chain);
            return;
        }

        final boolean intraNodeRequest = request.remoteAddress() == null;

        if (intraNodeRequest) {
            log.debug("TYPE: intra node request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        }

        final Object authHeader = request.getHeader("armor_authenticated_transport_request");
        boolean interNodeAuthenticated = false;

        if (authHeader != null && authHeader instanceof String) {
            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, ArmorService.getSecretKey());

            if (decrypted != null && (decrypted instanceof String) && decrypted.equals("authorized")) {
                interNodeAuthenticated = true;
            }

        }

        if (interNodeAuthenticated) {
            log.debug("TYPE: inter node cluster request, skip filters");
            chain.proceed(task, action, request, listener);
            return;
        }

        final Object transportCreds = request.getHeader("armor_transport_creds");
        User authenticatedTransportUser = null;
        boolean transportAuthenticated = false;
        if (transportCreds != null && transportCreds instanceof String
                && settings.getAsBoolean(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, false)) {

            try {

                final String decodedBasicHeader = new String(DatatypeConverter.parseBase64Binary((String) transportCreds),
                        StandardCharsets.US_ASCII);

                final String username = decodedBasicHeader.split(":")[0];
                final char[] password = decodedBasicHeader.split(":")[1].toCharArray();

                authenticatedTransportUser = backend.authenticate(new AuthCredentials(username, password));
                authorizator.fillRoles(authenticatedTransportUser, new AuthCredentials(authenticatedTransportUser.getName(), null));
                request.putInContext("armor_authenticated_user", authenticatedTransportUser);
            } catch (final Exception e) {
                throw new RuntimeException("Transport authentication failed due to " + e, e);
            }

        }

        transportAuthenticated = authenticatedTransportUser != null;

        if (transportAuthenticated) {
            log.debug("TYPE: transport authenticated request, apply filters");
            applySecure(task, action, request, listener, chain);
            return;
        }

        throw new RuntimeException("Unauthenticated request (SEARCHGUARD_UNAUTH_REQ) for action " + action);
    }

    public abstract void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener,
            final ActionFilterChain chain);

    @Override
    public final void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);

    }
    
    protected static <T> T getFromContextOrHeader(final String key, final TransportRequest request, final T defaultValue) {

        if (request.hasInContext(key)) {
            return request.getFromContext(key);
        }

        if (request.hasHeader(key)) {
            return (T) SecurityUtil.decryptAnDeserializeObject((String) request.getHeader(key), ArmorService.getSecretKey());
        }

        return defaultValue;
    }

    protected SearchRequest toSearchRequest(final GetRequest request) {

        final SearchRequest searchRequest = new SearchRequest();
        searchRequest.routing(request.routing());
        searchRequest.copyContextFrom(request);
        searchRequest.preference(request.preference());
        searchRequest.indices(request.indices());
        searchRequest.types(request.type());
        searchRequest.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder(request.type()).addIds(request.id())));
        return searchRequest;

    }

    protected MultiSearchRequest toMultiSearchRequest(final MultiGetRequest multiGetRequest) {

        final MultiSearchRequest msearch = new MultiSearchRequest();
        msearch.copyContextFrom(multiGetRequest);

        for (final Iterator<Item> iterator = multiGetRequest.iterator(); iterator.hasNext();) {
            final Item item = iterator.next();

            final SearchRequest st = new SearchRequest();
            st.routing(item.routing());
            st.indices(item.indices());
            st.types(item.type());
            st.preference(multiGetRequest.preference());
            st.source(SearchSourceBuilder.searchSource().query(new IdsQueryBuilder(item.type()).addIds(item.id())));
            msearch.add(st);
        }

        return msearch;

    }

    protected void doGetFromSearchRequest(final GetRequest getRequest, final SearchRequest searchRequest, final ActionListener listener, final Client client) {
        client.search(searchRequest, new DelegatingActionListener<SearchResponse, GetResponse>(listener) {
            @Override
            public GetResponse getDelegatedFromInstigator(final SearchResponse searchResponse) {

                if (searchResponse.getHits().getTotalHits() <= 0) {
                    return new GetResponse(new GetResult(getRequest.index(), getRequest.type(), getRequest.id(), getRequest.version(), false, null,
                            null));
                } else if (searchResponse.getHits().getTotalHits() > 1) {
                    throw new RuntimeException("cannot happen");
                } else {
                    final SearchHit sh = searchResponse.getHits().getHits()[0];
                    return new GetResponse(new GetResult(sh.index(), sh.type(), sh.id(), sh.version(), true, sh.getSourceRef(), null));
                }

            }
        });
    }

    protected void doGetFromSearchRequest(final MultiGetRequest getRequest, final MultiSearchRequest searchRequest, final ActionListener listener, final Client client) {
        client.multiSearch(searchRequest, new DelegatingActionListener<MultiSearchResponse, GetResponse>(listener) {
            @Override
            public GetResponse getDelegatedFromInstigator(final MultiSearchResponse searchResponse) {

                if (searchResponse.getResponses() == null || searchResponse.getResponses().length <= 0) {
                    final Item item = getRequest.getItems().get(0);
                    return new GetResponse(new GetResult(item.index(), item.type(), item.id(), item.version(), false, null, null));
                } else if (searchResponse.getResponses().length > 1) {
                    throw new RuntimeException("cannot happen");
                } else {
                    final org.elasticsearch.action.search.MultiSearchResponse.Item item = searchResponse.getResponses()[0];
                    final SearchHit sh = item.getResponse().getHits().getHits()[0];
                    return new GetResponse(new GetResult(sh.index(), sh.type(), sh.id(), sh.version(), true, sh.getSourceRef(), null));
                }

            }
        });
    }

    protected TokenEvaluator.Evaluator getEvaluator(final ActionRequest request, final String action, final User user) {

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();        
        final TokenEvaluator evaluator = new TokenEvaluator(armorConfigService.getSecurityConfiguration());


        final boolean allowedForAllIndices = !SecurityUtil.isWildcardMatch(action, "*put*", false)
                && !SecurityUtil.isWildcardMatch(action, "*delete*", false)
                && !SecurityUtil.isWildcardMatch(action, "indices:data*", false)
                && !SecurityUtil.isWildcardMatch(action, "cluster:admin*", false)
                && !SecurityUtil.isWildcardMatch(action, "*close*", false) && !SecurityUtil.isWildcardMatch(action, "*open*", false)
                && !SecurityUtil.isWildcardMatch(action, "*update*", false) && !SecurityUtil.isWildcardMatch(action, "*create*", false);

        if (request instanceof IndicesRequest) {
            final IndicesRequest ir = (IndicesRequest) request;
            addType(ir, types, action);
            log.trace("Indices {}", Arrays.toString(ir.indices()));
            log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
            log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

            try {
                ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
            } catch (java.lang.NullPointerException e) {
            }

            if (!allowedForAllIndices && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                log.error("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
            }

        }

        if (request instanceof CompositeIndicesRequest) {
            final CompositeIndicesRequest irc = (CompositeIndicesRequest) request;
            final List irs = irc.subRequests();
            for (final Iterator iterator = irs.iterator(); iterator.hasNext();) {
                final IndicesRequest ir = (IndicesRequest) iterator.next();
                addType(ir, types, action);
                log.trace("C Indices {}", Arrays.toString(ir.indices()));
                log.trace("Indices opts allowNoIndices {}", ir.indicesOptions().allowNoIndices());
                log.trace("Indices opts expandWildcardsOpen {}", ir.indicesOptions().expandWildcardsOpen());

                ci.addAll(resolveAliases(Arrays.asList(ir.indices())));
                aliases.addAll(getOnlyAliases(Arrays.asList(ir.indices())));
                if (!allowedForAllIndices
                        && (ir.indices() == null || Arrays.asList(ir.indices()).contains("_all") || ir.indices().length == 0)) {
                    log.error("Attempt from " + request.remoteAddress() + " to _all indices for " + action + "and " + user);
                    auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                    throw new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user);
                }

            }
        }

        if (!settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_NON_LOOPBACK_QUERY_ON_ARMOR_INDEX, false) && ci.contains(settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX))) {
            log.error("Attemp from " + request.remoteAddress() + " on " + settings.get(ConfigConstants.ARMOR_CONFIG_INDEX_NAME, ConfigConstants.DEFAULT_SECURITY_CONFIG_INDEX));
            auditListener.onMissingPrivileges(user.getName(), request);
            throw new ForbiddenException("Only allowed from localhost (loopback)");
        }

        if (ci.contains("_all")) {
            ci.clear();

            if (!allowedForAllIndices) {
                ci.add("*");
            }

        }

        final InetAddress resolvedAddress = request.getFromContext("armor_resolved_rest_address");

        if (resolvedAddress == null) {
            //not a rest request
            log.debug("Not a rest request, will ignore host rules");

        }

        try { 
            final TokenEvaluator.Evaluator eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user);
            request.putInContext("armor_ac_evaluator", eval);
            return eval;
        } catch (MalformedConfigurationException ex) {
            log.warn("Error in configuration");
            return null;
        }
    }

    //works also with alias of an alias!
    protected List<String> resolveAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final SortedMap<String, AliasOrIndex> aliases = clusterService.state().metaData().getAliasAndIndexLookup();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final AliasOrIndex indexAliases = aliases.get(index);

            if (!indexAliases.isAlias()) {
                result.add(index);
                log.trace("{} is an concrete index", index);
                continue;
            }

            log.trace("{} is an alias and points to -> {}", index, indexAliases.getIndices());

            final Iterable<Tuple<String, AliasMetaData>> iterable = ((AliasOrIndex.Alias) indexAliases).getConcreteIndexAndAliasMetaDatas();

            for (final Iterator<Tuple<String, AliasMetaData>> iterator = iterable.iterator(); iterator.hasNext();) {
                final Tuple<String, AliasMetaData> entry = iterator.next();
                result.add(entry.v1());
            }

        }

        return result;

    }

    protected List<String> getOnlyAliases(final List<String> indices) {

        final List<String> result = new ArrayList<String>();

        final SortedMap<String, AliasOrIndex> aliases = clusterService.state().metaData().getAliasAndIndexLookup();

        for (int i = 0; i < indices.size(); i++) {
            final String index = indices.get(i);

            final AliasOrIndex indexAliases = aliases.get(index);

            if (indexAliases.isAlias()) {
                result.add(index);
            }
        }

        return result;

    }

    protected void addType(final IndicesRequest request, final List<String> typesl, final String action) {

        try {
            final Method method = request.getClass().getDeclaredMethod("type");
            method.setAccessible(true);
            final String type = (String) method.invoke(request);
            typesl.add(type);
        } catch (final Exception e) {
            try {
                final Method method = request.getClass().getDeclaredMethod("types");
                method.setAccessible(true);
                final String[] types = (String[]) method.invoke(request);
                typesl.addAll(Arrays.asList(types));
            } catch (final Exception e1) {
                log.debug("Cannot determine types for {} ({}) due to type[s]() method not found", action, request.getClass());
            }

        }

    }

}
