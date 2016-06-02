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
import com.petalmd.armor.authentication.LdapUser;
import com.petalmd.armor.authentication.User;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.get.GetRequest;
import org.elasticsearch.action.get.MultiGetRequest;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.filter.level.ArmorWrapperQueryBuilder;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.ExistsQueryBuilder;
import org.elasticsearch.index.query.QueryBuilder;
import org.elasticsearch.index.query.TermQueryBuilder;
import org.elasticsearch.search.lookup.SourceLookup;
import org.elasticsearch.tasks.Task;

public class DLSActionFilter extends AbstractActionFilter {

    private final String filterType = "dlsfilter";
    private final Map<String, List<String>> filterMap = new HashMap<String, List<String>>();
    private final Client client;
    protected final boolean rewriteGetAsSearch;

    @Inject
    public DLSActionFilter(final Settings settings, final Client client, final AuthenticationBackend backend,
            final Authorizator authorizator, final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);
        this.client = client;

        final String[] arFilters = settings.getAsArray(ConfigConstants.ARMOR_DLSFILTER);
        for (int i = 0; i < arFilters.length; i++) {
            final String filterName = arFilters[i];

            final List<String> filters = Arrays.asList(settings.getAsArray("armor." + filterType + "." + filterName, new String[0]));

            filterMap.put(filterName, filters);
        }

        this.rewriteGetAsSearch = settings.getAsBoolean(ConfigConstants.ARMOR_REWRITE_GET_AS_SEARCH, true);
    }

    @Override
    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (filterMap.size() == 0) {
            chain.proceed(task, action, request, listener);
            return;
        }

        if (request instanceof SearchRequest || request instanceof MultiSearchRequest || request instanceof GetRequest
                || request instanceof MultiGetRequest) {

            final List<String> _filters = new ArrayList<String>();
            for (final Iterator<Entry<String, List<String>>> it = filterMap.entrySet().iterator(); it.hasNext();) {

                final Entry<String, List<String>> entry = it.next();

                final String filterName = entry.getKey();
                final List<String> filters = entry.getValue();

                if (request.hasInContext("armor_filter")) {
                    if (!((List<String>) request.getFromContext("armor_filter")).contains(filterType + ":" + filterName)) {
                        ((List<String>) request.getFromContext("armor_filter")).add(filterType + ":" + filterName);
                        _filters.add(filterType + ":" + filterName);
                    }
                } else {
                    _filters.add(filterType + ":" + filterName);
                    request.putInContext("armor_filter", _filters);
                }

                request.putInContext("armor." + filterType + "." + filterName + ".filters", filters);

                log.trace("armor." + filterType + "." + filterName + ".filters {}", filters);
            }
            final User user = request.getFromContext("armor_authenticated_user", null);
            final Object authHeader = request.getHeader("armor_authenticated_transport_request");

            final TokenEvaluator.Evaluator evaluator;

            try {
                evaluator = getFromContextOrHeader("armor_ac_evaluator", request, getEvaluator(request, action, user));
            } catch (ForbiddenException e) {
                listener.onFailure(e);
                throw e;
            }
            request.putInContext("_armor_token_evaluator", evaluator);
//

            if (request.remoteAddress() == null && user == null) {
                log.trace("Return on INTERNODE request");
                return;
            }

            if (evaluator.getBypassAll() && user != null) {
                log.trace("Return on WILDCARD for " + user);
                return;
            }

            log.trace("user {}", user);

            if (user == null) {

                if (authHeader == null || !(authHeader instanceof String)) {
                    log.error("not authenticated");
                    throw new ElasticsearchException("not authenticated");
                }

                final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, ArmorService.getSecretKey());

                if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                    log.error("bad authenticated");
                    throw new ElasticsearchException("bad authentication");
                }

            }

            //here we know that we either have a non null user or an internally authenticated internode request
            log.trace("filter for {}", _filters);

            for (int i = 0; i < _filters.size(); i++) {
                final String[] f = _filters.get(i).split(":");
                final String ft = f[0];
                final String fn = f[1];

                if (!ft.contains("dlsfilter")) { //does only dls Stuff 
                    log.trace("    {} skipped here", ft);
                    continue;
                }

                log.trace("Apply {}/{} for {}", ft, fn, request.getClass());

                final TokenEvaluator.FilterAction faction = evaluator.evaluateFilter(ft, fn);

                if (faction == TokenEvaluator.FilterAction.BYPASS) {
                    log.debug("will bypass");
                    continue;
                }

                if (rewriteGetAsSearch && request instanceof GetRequest) {
                    log.debug("Rewrite GetRequest as SearchRequest");
                    SearchRequest sr = toSearchRequest((GetRequest) request);
                    if (addFiltersToSearchRequest(sr, user, fn) != null) {
                        this.doGetFromSearchRequest((GetRequest) request, sr, listener, client);
                    } else {
                        log.warn("Error during the parsing of the SearchRequest, aborting the request");
                    }
                    return;
                }

                if (rewriteGetAsSearch && request instanceof MultiGetRequest) {
                    log.debug("Rewrite GetRequest as SearchRequest");
                    MultiGetRequest multiGetRequest = (MultiGetRequest) request;
                    MultiSearchRequest mSRequest = toMultiSearchRequest(multiGetRequest);
                    for (SearchRequest sr : mSRequest.requests()) {
                        if (addFiltersToSearchRequest(sr, user, fn) == null) {
                            log.warn("Couldn't parse this request in MultiSearch Request, aborting the Request");
                            return;
                        }
                    }
                    this.doGetFromSearchRequest((MultiGetRequest) request, mSRequest, listener, client);
                    return;
                }

                if (request instanceof SearchRequest) {
                    log.debug("Search Request Rewrite");
                    if (addFiltersToSearchRequest((SearchRequest) request, user, fn) == null) {
                        log.warn("couldn't rewrite the search, Aborting the request");
                        return;
                    }
                    SearchRequest sr = (SearchRequest) request;

                }

                if (request instanceof MultiSearchRequest) {
                    log.debug("MultiSearchRequestRewrite");
                    for (SearchRequest sr : ((MultiSearchRequest) request).requests()) {
                        if (addFiltersToSearchRequest(sr, user, fn) == null) {
                            log.warn("Couldn't parse this multiSearchRequest, aborting the request");
                            return;
                        }
                    }
                }
            }

            chain.proceed(task, action, request, listener);
        }
    }

    private SearchRequest addFiltersToSearchRequest(SearchRequest sr, final User user, String fn) {

        log.debug("Modifiy search filters for query {} and index {} requested from {} and {}/{}", "SearchRequest",
                Arrays.toString(sr.indices()), sr.remoteAddress(), "dlsfilter", fn);

        if(!filterMap.containsKey(fn)){
            return sr;
        }
        
        final List<String> list = filterMap.get(fn);

        //log.trace("filterStrings {}", list);
        final List<QueryBuilder> qliste = new ArrayList<QueryBuilder>();

        if (list.isEmpty()) {
            return sr;
        }

        final String tfilterType = list.get(0);

        log.trace("DLS: {} {}", tfilterType, list);

        switch (tfilterType) {

            case "term": {

                final boolean negate = Boolean.parseBoolean(list.get(3));
                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(list.get(1), list.get(2))));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(list.get(1), list.get(2))));
                }
            }

            break;
            case "user_name": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                final String field = list.get(1);
                final boolean negate = Boolean.parseBoolean(list.get(2));
                final String username = user.getName();
                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, username)));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, username)));
                }
            }

            break;
            case "user_roles": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                final String field = list.get(1);
                final boolean negate = Boolean.parseBoolean(list.get(2));

                final List<QueryBuilder> inner = new ArrayList<QueryBuilder>();
                for (final Iterator iterator = user.getRoles().iterator(); iterator.hasNext();) {
                    final String role = (String) iterator.next();
                    if (negate) {
                        inner.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, role)));
                    } else {
                        inner.add(new TermQueryBuilder(field, role));
                    }
                }

                BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
                for (QueryBuilder innerFilter : inner) {
                    if (negate) {
                        boolQueryBuilder.filter(innerFilter);
                    } else {
                        boolQueryBuilder.should(innerFilter);
                    }
                }
                qliste.add(boolQueryBuilder);
            }
            ;
            break;
            case "ldap_user_attribute": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                if (!(user instanceof LdapUser)) {
                    throw new ElasticsearchException("user is not an ldapuser");
                }

                final LdapUser ldapUser = (LdapUser) user;

                final String field = list.get(1);
                final String attribute = list.get(2);
                final boolean negate = Boolean.parseBoolean(list.get(3));
                final Attribute attr = ldapUser.getUserEntry().get(attribute);

                if (attribute == null) {
                    break;
                }

                try {
                    if (negate) {
                        qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, attr.getString())));
                    } else {
                        qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, attr.getString())));
                    }
                } catch (final LdapInvalidAttributeValueException e) {
                    throw new RuntimeException("Error in ldap user attribute", e);
                }

            }
            ;
            break;
            case "ldap_user_roles": {

                if (user == null) {
                    throw new ElasticsearchException("user is null");
                }

                if (!(user instanceof LdapUser)) {
                    throw new ElasticsearchException("user is not an ldapuser");
                }

                final LdapUser ldapUser = (LdapUser) user;

                final String field = list.get(1);
                final String attribute = list.get(2);
                final boolean negate = Boolean.parseBoolean(list.get(3));

                final List<QueryBuilder> inner = new ArrayList<QueryBuilder>();
                for (final Iterator<org.apache.directory.api.ldap.model.entry.Entry> iterator = ldapUser.getRoleEntries().iterator(); iterator.hasNext();) {
                    final org.apache.directory.api.ldap.model.entry.Entry roleEntry = iterator.next();

                    try {

                        if (negate) {
                            qliste.add(new BoolQueryBuilder().mustNot(new TermQueryBuilder(field, roleEntry.get(attribute).getString())));
                        } else {
                            qliste.add(new BoolQueryBuilder().filter(new TermQueryBuilder(field, roleEntry.get(attribute).getString())));
                        }
                    } catch (final LdapInvalidAttributeValueException e) {
                        throw new RuntimeException("Error in ldap user attribute", e);
                    }

                }
                BoolQueryBuilder boolQueryBuilder = new BoolQueryBuilder();
                for (QueryBuilder innerFilter : inner) {
                    if (negate) {
                        boolQueryBuilder.filter(innerFilter);
                    } else {
                        boolQueryBuilder.should(innerFilter);
                    }
                }
                qliste.add(boolQueryBuilder);
            }
            ;
            break;
            case "exists": {
                final boolean negate = Boolean.parseBoolean(list.get(2));
                final ExistsQueryBuilder existQueryBuilder = new ExistsQueryBuilder(list.get(1));

                if (negate) {
                    qliste.add(new BoolQueryBuilder().mustNot(existQueryBuilder));
                } else {
                    qliste.add(new BoolQueryBuilder().filter(existQueryBuilder));
                }
            }
            ;
            break;
        }

        final BoolQueryBuilder dlsBoolQuery = new BoolQueryBuilder();
        for (QueryBuilder innerFilter : qliste) {
            dlsBoolQuery.filter(innerFilter);
        }

        if (!qliste.isEmpty()) {
            final SourceLookup sl = new SourceLookup();
            BytesReference srSource;
            for (int i = 0; i < 2; i++) {
                if (i == 0) {
                    srSource = sr.source();
                } else {
                    srSource = sr.extraSource();
                }
                if (srSource != null) {
                    sl.setSource(srSource);
                    if (sl.isEmpty()) { //WARNING : this also initialize the sourceLookup for following sl.soure() call, so DO NOT REMOVE.
                        continue;
                    }
                    try {
                        final BoolQueryBuilder sourceQueryBuilder = new BoolQueryBuilder();
                        final Map<String, Object> query = (Map<String, Object>) (sl.extractValue("query"));
                        sourceQueryBuilder.filter(dlsBoolQuery);
                        sourceQueryBuilder.must(new ArmorWrapperQueryBuilder(query));
                        String queryString = sourceQueryBuilder.toString();
                        log.debug("final query of ExtraSource is :\n" + queryString);
                        Map<String, Object> fullQueryMap = XContentHelper.convertToMap(sourceQueryBuilder.buildAsBytes(XContentType.JSON), false).v2();
                        Map<String, Object> sourceMap = sl.source();
                        sourceMap.put("query", fullQueryMap);
                        if (i == 0) {
                            sr.source(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                        } else {
                            sr.extraSource(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                        }
                    } catch (Exception e) {
                        String source = sl.toString();
                        log.warn("Error during extract of query in the source, aborting the request." + source);
                        return null;
                    }
                }
            }
        }
        log.debug("Search request is now : \n" + sr.source().toUtf8());

        return sr;

    }

}
