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
package com.petalmd.armor.filter;

import com.petalmd.armor.audit.AuditListener;
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
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import static com.petalmd.armor.filter.AbstractActionFilter.getFromContextOrHeader;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.fetch.source.FetchSourceParseElement;
import org.elasticsearch.search.lookup.SourceLookup;
import org.elasticsearch.tasks.Task;

public class FLSActionFilter extends AbstractActionFilter {

    private final String filterType = "flsfilter";
    private final Map<String, Tuple<List<String>, List<String>>> filterMap = new HashMap<String, Tuple<List<String>, List<String>>>();
    private final Client client;
    protected final boolean rewriteGetAsSearch;

    @Inject
    public FLSActionFilter(final Settings settings, final Client client, final AuthenticationBackend backend,
            final Authorizator authorizator, final ClusterService clusterService, final ArmorConfigService armorConfigService, final AuditListener auditListener) {
        super(settings, backend, authorizator, clusterService, armorConfigService, auditListener);

        this.client = client;

        final String[] arFilters = settings.getAsArray(ConfigConstants.ARMOR_FLSFILTER);
        for (int i = 0; i < arFilters.length; i++) {
            final String filterName = arFilters[i];

            final List<String> sourceIncludes = Arrays.asList(settings.getAsArray("armor." + filterType + "." + filterName
                    + ".source_includes", new String[0]));
            final List<String> sourceExcludes = Arrays.asList(settings.getAsArray("armor." + filterType + "." + filterName
                    + ".source_excludes", new String[0]));

            filterMap.put(filterName, new Tuple<List<String>, List<String>>(sourceIncludes, sourceExcludes));
        }

        this.rewriteGetAsSearch = settings.getAsBoolean(ConfigConstants.ARMOR_REWRITE_GET_AS_SEARCH, true);
    }

    @Override
    public void applySecure(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        if (filterMap.size() == 0) {
            chain.proceed(task, action, request, listener);
            return;
        }

        final List<String> _filters = new ArrayList<String>();
        for (final Iterator<Entry<String, Tuple<List<String>, List<String>>>> it = filterMap.entrySet().iterator(); it.hasNext();) {

            final Entry<String, Tuple<List<String>, List<String>>> entry = it.next();

            final String filterName = entry.getKey();
            final List<String> sourceIncludes = entry.getValue().v1();
            final List<String> sourceExcludes = entry.getValue().v2();

            request.putInContext("armor." + filterType + "." + filterName + ".source_includes", sourceIncludes);
            request.putInContext("armor." + filterType + "." + filterName + ".source_excludes", sourceExcludes);

            if (request.hasInContext("armor_filter") && filterType != null) {
                if (!((List<String>) request.getFromContext("armor_filter")).contains(filterType + ":" + filterName)) {
                    ((List<String>) request.getFromContext("armor_filter")).add(filterType + ":" + filterName);
                    _filters.add(filterType + ":" + filterName);
                }
            } else if (filterType != null) {
                _filters.add(filterType + ":" + filterName);
                request.putInContext("armor_filter", _filters);
            }

            log.trace("armor." + filterType + "." + filterName + ".source_includes", sourceIncludes);
            log.trace("armor." + filterType + "." + filterName + ".source_excludes", sourceExcludes);

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
        List<String> sourceIncludes = new ArrayList<>();
        List<String> sourceExcludes = new ArrayList<>();
        for (int i = 0; i < _filters.size(); i++) {
            final String[] f = _filters.get(i).split(":");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Apply {}/{} for {}", ft, fn, request.getClass());

            final TokenEvaluator.FilterAction faction = evaluator.evaluateFilter(ft, fn);

            if (faction == TokenEvaluator.FilterAction.BYPASS) {
                log.debug("will bypass");
                continue;
            }

            sourceIncludes.addAll(filterMap.get(fn).v1());
            sourceExcludes.addAll(filterMap.get(fn).v2());

        }

        if (rewriteGetAsSearch && request instanceof GetRequest) {
            SearchRequest sr = toSearchRequest((GetRequest) request);
            if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) != null) {
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
                if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) == null) {
                    log.warn("Couldn't parse this request in MultiSearch Request, aborting the Request");
                    return;
                }
            }
            this.doGetFromSearchRequest((MultiGetRequest) request, toMultiSearchRequest((MultiGetRequest) request), listener, client);
            return;
        }

        if (request instanceof SearchRequest) {
            log.debug("Search Request Rewrite");
            if (addFiltersToSearchRequest((SearchRequest) request, user, sourceIncludes, sourceExcludes) == null) {
                log.warn("couldn't rewrite the search, Aborting the request");
                return;
            }
            SearchRequest sr = (SearchRequest) request;

        }

        if (request instanceof MultiSearchRequest) {
            log.debug("MultiSearchRequestRewrite");
            for (SearchRequest sr : ((MultiSearchRequest) request).requests()) {
                if (addFiltersToSearchRequest(sr, user, sourceIncludes, sourceExcludes) == null) {
                    log.warn("Couldn't parse this multiSearchRequest, aborting the request");
                    return;
                }
            }
        }

        chain.proceed(task, action, request, listener);
    }

    private SearchRequest addFiltersToSearchRequest(SearchRequest sr, final User user, final List<String> sourceIncludes, final List<String> sourceExcludes) {

        if (log.isDebugEnabled()) {
            log.debug("Modifiy search filters for query {} and index {} requested from {} and {}/[Includes: {}, Excludes: {}]", "SearchRequest",
                    Arrays.toString(sr.indices()), sr.remoteAddress(), filterType, Arrays.toString(sourceIncludes.toArray()), Arrays.toString(sourceExcludes.toArray()));
        }

        if (sourceIncludes.isEmpty() && sourceExcludes.isEmpty()) {
            return sr;
        }

        SourceLookup sl = new SourceLookup();
        for (int i = 0; i < 2; i++) {

            BytesReference source = null;
            if (i == 0) {
                source = sr.source();
            } else {
                source = sr.extraSource();
            }
            if (source != null) {
                sl.setSource(source);
                if (sl.isEmpty()) { //WARNING : this also initialize the sourceLookup for(sl.soure() call), so DO NOT REMOVE.
                    continue;
                }
                try {
                    Map<String, Object> sourceMap = sl.source();

                    //fields parameter
                    if (sl.containsKey("fields")) {
                        final List<String> fields = (List<String>) sl.extractValue("fields");
                        final List<String> survivingFields = new ArrayList<String>(fields);
                        for (final Iterator<String> iterator = fields.iterator(); iterator.hasNext();) {
                            final String field = iterator.next();

                            for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext();) {
                                final String exclude = iteratorExcludes.next();
                                if (field.startsWith("_source.") || SecurityUtil.isWildcardMatch(field, exclude, false)) { //we remove any field request starting with '_source.' since it should not be used (If the field is legit, it works without prefixing by '_source.'). 
                                    survivingFields.remove(field);
                                }
                            }
                        }
                        log.trace("survivingFields {}", survivingFields.equals(fields) ? "-all-" : survivingFields.toString());
                        fields.retainAll(survivingFields);
                        sourceMap.put("fields", fields);
                    } else {
                        Map<String, Object> sourceQuery = (Map<String, Object>) sl.extractValue("_source");
                        if (sourceQuery == null) {
                            sourceQuery = new HashMap<>();
                        }
                        //_source parameter
                        List<String> finalSourceIncludes = null;
                        List<String> finalSourceExcludes = null;
                        if (!sourceQuery.isEmpty()) {
                            FetchSourceParseElement fetchSourceParseElement = new FetchSourceParseElement();
                            XContentBuilder builder = XContentFactory.jsonBuilder().map(sourceQuery);
                            XContentParser parser = XContentType.JSON.xContent().createParser(builder.string());
                            FetchSourceContext fSContext = fetchSourceParseElement.parse(parser);
                            if (fSContext.fetchSource() != false) {
                                final List<String> fields = fSContext.includes() != null ? Arrays.asList(fSContext.includes()) : new ArrayList<String>();
                                final List<String> survivingFields = new ArrayList<String>(fields);
                                for (final Iterator<String> iterator = fields.iterator(); iterator.hasNext();) {
                                    final String field = iterator.next();
                                    //remove Fields from Excludes
                                    for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext();) {
                                        final String exclude = iteratorExcludes.next();
                                        if (SecurityUtil.isWildcardMatch(field, exclude, false)) {
                                            survivingFields.remove(field);
                                        }
                                    }
                                }
                                log.trace("survivingFields {}", survivingFields.equals(fields) ? "-all-" : survivingFields.toString());
                                fields.retainAll(survivingFields);
                                finalSourceIncludes = fields;
                                finalSourceExcludes = new ArrayList(sourceExcludes);
                                if (fSContext.excludes() != null) {
                                    finalSourceExcludes.addAll(fields);
                                }
                            }
                        } else {
                            finalSourceIncludes = sourceIncludes;
                            finalSourceExcludes = sourceExcludes;
                        }
                        sourceQuery.clear();
                        if (finalSourceIncludes != null && !finalSourceIncludes.isEmpty()) {
                            sourceQuery.put("include", finalSourceIncludes);
                        }
                        if (finalSourceExcludes != null && !finalSourceExcludes.isEmpty()) {
                            sourceQuery.put("exclude", finalSourceExcludes);
                        }
                        sourceMap.put("_source", sourceQuery);
                    }
                    if (i == 0) {
                        sr.source(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                    } else {
                        sr.extraSource(XContentFactory.jsonBuilder().map(sourceMap).bytes());
                    }
                } catch (Exception e) {
                    log.warn("Couldn't apply the FLS Filter, aborting the query", e);
                    return null;
                }
            }
        }

        return sr;
    }

}
