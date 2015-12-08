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

package com.petalmd.armor.filter.level;

import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.LdapUser;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator.Evaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.FilterAction;
import com.petalmd.armor.util.SecurityUtil;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.lucene.index.Term;
import org.apache.lucene.queries.TermFilter;
import org.apache.lucene.search.*;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.lucene.search.Queries;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.ParsedQuery;
import org.elasticsearch.search.fetch.source.FetchSourceContext;
import org.elasticsearch.search.internal.SearchContext;
import org.elasticsearch.search.internal.ShardSearchRequest;
import org.elasticsearch.search.internal.ShardSearchTransportRequest;
import org.elasticsearch.transport.TransportRequest;

import java.util.*;

public class ConfigurableSearchContextCallback implements SearchContextCallback {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final AuditListener auditListener;

    public ConfigurableSearchContextCallback(final Settings settings, final AuditListener auditListener) {

        if (auditListener == null) {
            throw new IllegalArgumentException("auditListener must not be null");
        }
        this.auditListener = auditListener;

    }

    private static <T> T getFromContextOrHeader(final String key, final TransportRequest request, final T defaultValue) {

        if (request.hasInContext(key)) {
            return request.getFromContext(key);
        }

        if (request.hasHeader(key)) {
            return (T) SecurityUtil.decryptAnDeserializeObject((String) request.getHeader(key), ArmorService.getSecretKey());
        }

        return defaultValue;
    }

    @Override
    public void onCreateContext(final SearchContext context, final ShardSearchRequest ssRequest) {
        try {
            onCreateContext0(context, ssRequest);
        } catch (final Exception e) {
            log.error("Error onCreateContext() {} ", e, e.toString());
            throw new RuntimeException(e);
        }
    }

    private void onCreateContext0(final SearchContext context, final ShardSearchRequest ssRequest) {

        if (ssRequest instanceof ShardSearchTransportRequest) {
            final ShardSearchTransportRequest request = (ShardSearchTransportRequest) ssRequest;

            final List<String> filter = getFromContextOrHeader("armor_filter", request, Collections.EMPTY_LIST);

            if (filter.size() == 0) {
                log.trace("No filters, skip");
                return;
            }

            final Evaluator evaluator = getFromContextOrHeader("armor_ac_evaluator", request, (Evaluator) null);
            final User user = getFromContextOrHeader("armor_authenticated_user", request, null);

            if (request.remoteAddress() == null && user == null) {
                log.trace("Return on INTERNODE request");
                return;
            }

            if (evaluator.getBypassAll() && user != null) {
                log.trace("Return on WILDCARD for " + user);
                return;
            }

            //log.trace("user {}", user);

            final Object authHeader = getFromContextOrHeader("armor_authenticated_transport_request", request, null);

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
            log.trace("filter for {}", filter);

            for (int i = 0; i < filter.size(); i++) {
                final String[] f = filter.get(i).split(":");
                final String ft = f[0];
                final String fn = f[1];

                if (!ft.contains("dlsfilter") && !ft.contains("flsfilter")) {
                    log.trace("    {} skipped here", ft);
                    continue;
                }

                log.trace("Apply {}/{} for {}", ft, fn, request.getClass());

                final FilterAction faction = evaluator.evaluateFilter(ft, fn);

                if (faction == FilterAction.BYPASS) {
                    log.debug("will bypass");
                    continue;
                }

                log.trace("Modifiy search context for node {} and index {} requested from {} and {}/{}", context.shardTarget().nodeId(),
                        Arrays.toString(request.indices()), request.remoteAddress(), ft, fn);

                if ("dlsfilter".equals(ft)) {
                    final List<String> list = getFromContextOrHeader("armor." + ft + "." + fn + ".filters", request,
                            Collections.EMPTY_LIST);

                    //log.trace("filterStrings {}", list);

                    final ParsedQuery origfilter = context.parsedPostFilter();
                    final List<Query> qliste = new ArrayList<Query>();

                    if (list.isEmpty()) {
                        continue;
                    }

                    final String tfilterType = list.get(0);

                    log.trace("DLS: {} {}", tfilterType, list);

                    switch (tfilterType) {

                        case "term": {

                            final boolean negate = Boolean.parseBoolean(list.get(3));

                            if (negate) {
                                qliste.add(org.elasticsearch.common.lucene.search.Queries.not(new QueryWrapperFilter(new TermQuery(new Term(list.get(1), list.get(2))))));
                            } else {
                                qliste.add(new QueryWrapperFilter(new TermQuery(new Term(list.get(1), list.get(2)))));
                            }

                        }
                            ;
                            break;
                        case "user_name": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            final String field = list.get(1);
                            final boolean negate = Boolean.parseBoolean(list.get(2));
                            final String username = user.getName();

                            if (negate) {
                                qliste.add(org.elasticsearch.common.lucene.search.Queries.not(new QueryWrapperFilter(new TermQuery(new Term(field, username)))));
                            } else {
                                qliste.add(new QueryWrapperFilter(new TermQuery(new Term(field, username))));
                            }

                        }
                            ;
                            break;
                        case "user_roles": {

                            if (user == null) {
                                throw new ElasticsearchException("user is null");
                            }

                            final String field = list.get(1);
                            final boolean negate = Boolean.parseBoolean(list.get(2));

                            final List<Query> inner = new ArrayList<Query>();
                            for (final Iterator iterator = user.getRoles().iterator(); iterator.hasNext();) {
                                final String role = (String) iterator.next();

                                if (negate) {
                                    inner.add(Queries.not(
                                            (new QueryWrapperFilter(new TermQuery(new Term(field, role)))).getQuery()
                                    ));
                                } else {
                                    inner.add(new QueryWrapperFilter(new TermQuery(new Term(field, role))));
                                }

                            }

                            BooleanQuery boolQuery = new BooleanQuery();
                            for (Query innerFilter : inner) {
                                if (negate) {
                                    boolQuery.add(innerFilter, BooleanClause.Occur.MUST);
                                } else {
                                    boolQuery.add(innerFilter, BooleanClause.Occur.SHOULD);
                                }
                            }
                            qliste.add(new QueryWrapperFilter(boolQuery));
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
                                    qliste.add(org.elasticsearch.common.lucene.search.Queries.not(new TermFilter(new Term(field, attr.getString()))));
                                } else {
                                    qliste.add(new QueryWrapperFilter(new TermQuery(new Term(field, attr.getString()))));
                                }
                            } catch (final LdapInvalidAttributeValueException e) {
                                //no-op
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

                            final List<Query> inner = new ArrayList<Query>();
                            for (final Iterator<Entry> iterator = ldapUser.getRoleEntries().iterator(); iterator.hasNext();) {
                                final Entry roleEntry = iterator.next();

                                try {
                                    org.elasticsearch.common.lucene.search.Queries.not(
                                        new TermQuery(
                                            new Term(field, roleEntry.get(attribute).getString())
                                        )
                                    );
                                    if (negate) {
                                        inner.add(org.elasticsearch.common.lucene.search.Queries.not(new QueryWrapperFilter(new TermQuery((new Term(field, roleEntry.get(attribute).getString()))))));
                                    } else {
                                        inner.add(new QueryWrapperFilter(new TermQuery(new Term(field, roleEntry.get(attribute).getString()))));
                                    }
                                } catch (final LdapInvalidAttributeValueException e) {
                                    //no-op
                                }

                            }

                            BooleanQuery boolQuery = new BooleanQuery();
                            for (Query innerFilter : inner) {
                                if (negate) {
                                   boolQuery.add(innerFilter, BooleanClause.Occur.MUST);
                                } else {
                                    boolQuery.add(innerFilter, BooleanClause.Occur.SHOULD);
                                }
                            }
                            qliste.add(new QueryWrapperFilter(boolQuery));
                        }
                            ;
                            break;
                        case "exists": {
                            qliste.add(new FieldValueFilter(list.get(1), Boolean.parseBoolean(list.get(2))));
                        }
                            ;
                            break;
                    }

                    BooleanQuery boolQuery = new BooleanQuery();
                    for (Query innerFilter : qliste) {
                        boolQuery.add(innerFilter, BooleanClause.Occur.MUST);

                        if (origfilter == null) {
                            context.parsedPostFilter(new ParsedQuery(boolQuery));
                        } else {
                            context.parsedPostFilter(new ParsedQuery(boolQuery, origfilter.namedFilters()));
                        }
                    }
                }

                if ("flsfilter".equals(ft)) {

                    final List<String> sourceIncludes = getFromContextOrHeader("armor." + ft + "." + fn + ".source_includes",
                            request, Collections.EMPTY_LIST);
                    final List<String> sourceExcludes = getFromContextOrHeader("armor." + ft + "." + fn + ".source_excludes",
                            request, Collections.EMPTY_LIST);

                    log.trace("fls sourceIncludes {}", sourceIncludes);
                    log.trace("fls sourceExcludes {}", sourceExcludes);
                    boolean fieldsDone = false;

                    if (context.hasFieldNames()) {
                        fieldsDone = true;
                        final List<String> fields = context.fieldNames();
                        final List<String> survivingFields = new ArrayList<String>(fields);
                        for (final Iterator<String> iterator = fields.iterator(); iterator.hasNext();) {
                            final String field = iterator.next();

                            for (final Iterator<String> iteratorExcludes = sourceExcludes.iterator(); iteratorExcludes.hasNext();) {
                                final String exclude = iteratorExcludes.next();
                                if (SecurityUtil.isWildcardMatch(field, exclude, false)) {
                                    survivingFields.remove(field);
                                }

                            }

                            /*for (Iterator<String> iteratorIncludes = sourceIncludes.iterator(); iteratorIncludes.hasNext();) {
                                String include = iteratorIncludes.next();
                                if(SecurityUtil.isWildcardMatch(field, include, false)) {
                                    if(!survivingFields.contains(field)) {
                                        survivingFields.add(field);
                                    }
                                }

                            }*/

                        }

                        log.trace("survivingFields {}", survivingFields.equals(fields) ? "-all-" : survivingFields.toString());
                        fields.retainAll(survivingFields);
                    }

                    //TODO FUTURE include exclude precedence, what if null or empty?

                    if (!fieldsDone) {

                        context.fetchSourceContext(new FetchSourceContext(sourceIncludes.size() == 0 ? null : sourceIncludes
                                .toArray(new String[0]), sourceExcludes.size() == 0 ? null : sourceExcludes.toArray(new String[0])));
                    }

                }
            }

        } else {
            log.error("Cannot add DLS/FLS to a local ShardSearchRequest, {} not supported", ssRequest.getClass());
            throw new ElasticsearchException("Cannot add DLS/FLS to a local ShardSearchRequest, " + ssRequest.getClass() + " not supported");
        }
    }
}
