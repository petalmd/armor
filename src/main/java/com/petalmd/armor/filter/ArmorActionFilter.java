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

import java.io.Serializable;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.*;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.CompositeIndicesRequest;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.ClusterService;
import org.elasticsearch.cluster.metadata.AliasMetaData;
import org.elasticsearch.cluster.metadata.AliasOrIndex;
import org.elasticsearch.common.collect.ImmutableOpenMap;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.petalmd.armor.ArmorPlugin;
import com.petalmd.armor.audit.AuditListener;
import com.petalmd.armor.authentication.AuthException;
import com.petalmd.armor.authentication.User;
import com.petalmd.armor.authentication.backend.AuthenticationBackend;
import com.petalmd.armor.authorization.Authorizator;
import com.petalmd.armor.authorization.ForbiddenException;
import com.petalmd.armor.service.ArmorConfigService;
import com.petalmd.armor.service.ArmorService;
import com.petalmd.armor.tokeneval.TokenEvaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.Evaluator;
import com.petalmd.armor.tokeneval.TokenEvaluator.FilterAction;
import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;
import org.elasticsearch.index.IndexNotFoundException;
import org.elasticsearch.tasks.Task;

public class ArmorActionFilter implements ActionFilter {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final AuditListener auditListener;
    protected final Authorizator authorizator = null;
    protected final AuthenticationBackend authenticationBackend = null;
    protected final Settings settings;
    protected final ClusterService clusterService;
    protected final Client client;
    protected final ArmorConfigService armorConfigService;

    @Inject
    public ArmorActionFilter(final Settings settings, final AuditListener auditListener, final ClusterService clusterService,
            final Client client, final ArmorConfigService armorConfigService) {
        this.auditListener = auditListener;
        this.settings = settings;
        this.clusterService = clusterService;
        this.client = client;
        this.armorConfigService = armorConfigService;
    }

    @Override
    public int order() {
        return Integer.MIN_VALUE + 1;
    }

    @Override
    public void apply(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain) {

        try {
            apply0(task, action, request, listener, chain);
        } catch (final ForbiddenException e) {
            log.error("Forbidden while apply() due to {} for action {}", e, e.toString(), action);
            throw e;
        } catch (IndexNotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error while apply() due to {} for action {}", e, e.toString(), action);
            throw new RuntimeException(e);

        }
    }

    private void copyContextToHeader(final ActionRequest request) {
        if (ArmorPlugin.DLS_SUPPORTED) {

            final ImmutableOpenMap<Object, Object> map = request.getContext();

            final Iterator it = map.keysIt();

            while (it.hasNext()) {
                final Object key = it.next();

                if (key instanceof String && key.toString().startsWith("armor")) {

                    if (request.hasHeader(key.toString())) {
                        continue;
                    }

                    request.putHeader(key.toString(),
                            SecurityUtil.encryptAndSerializeObject((Serializable) map.get(key), ArmorService.getSecretKey()));
                    log.trace("Copy from context to header {}", key);

                }

            }

        }
    }

    private void apply0(Task task, final String action, final ActionRequest request, final ActionListener listener, final ActionFilterChain chain)
            throws Exception {
        //proceeding the chaing for kibana field stats request
        if (settings.getAsBoolean(ConfigConstants.ARMOR_ALLOW_KIBANA_ACTIONS, true) && (action.startsWith("cluster:monitor/") || action.contains("indices:data/read/field_stats"))) {
            chain.proceed(task, action, request, listener);
            return;
        }

        copyContextToHeader(request);

        log.trace("action {} ({}) from {}", action, request.getClass(), request.remoteAddress() == null ? "INTRANODE" : request
                .remoteAddress().toString());

        final User user = request.getFromContext("armor_authenticated_user", null);
        final Object authHeader = request.getHeader("armor_authenticated_transport_request");

        if (request.remoteAddress() == null && user == null) {
            log.trace("INTRANODE request");
            try {
                chain.proceed(task, action, request, listener);
            } catch (IndexNotFoundException e) {
                log.warn("Missing internal Armor Index, access granted");
                return;
            }

            return;
        }

        if (user == null) {

            if (authHeader == null || !(authHeader instanceof String)) {
                log.error("not authenticated");
                listener.onFailure(new AuthException("not authenticated"));
            }

            final Object decrypted = SecurityUtil.decryptAnDeserializeObject((String) authHeader, ArmorService.getSecretKey());

            if (decrypted == null || !(decrypted instanceof String) || !decrypted.equals("authorized")) {
                log.error("bad authenticated");
                listener.onFailure(new AuthException("bad authenticated"));
            }

            log.trace("Authenticated INTERNODE (cluster) message, pass through");
            chain.proceed(task, action, request, listener);
            return;
        }

        log.trace("user {}", user);

        final boolean allowedForAllIndices = !SecurityUtil.isWildcardMatch(action, "*put*", false)
                && !SecurityUtil.isWildcardMatch(action, "*delete*", false)
                && !SecurityUtil.isWildcardMatch(action, "indices:data*", false)
                && !SecurityUtil.isWildcardMatch(action, "cluster:admin*", false)
                && !SecurityUtil.isWildcardMatch(action, "*close*", false) && !SecurityUtil.isWildcardMatch(action, "*open*", false)
                && !SecurityUtil.isWildcardMatch(action, "*update*", false) && !SecurityUtil.isWildcardMatch(action, "*create*", false);

        final TokenEvaluator evaluator = new TokenEvaluator(armorConfigService.getSecurityConfiguration());
        final Evaluator eval;
        request.putInContext("_armor_token_evaluator", evaluator);

        final List<String> ci = new ArrayList<String>();
        final List<String> aliases = new ArrayList<String>();
        final List<String> types = new ArrayList<String>();

        if (request.getFromContext("armor_ac_evaluator") == null) {

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

                    listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
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

                        listener.onFailure(new ForbiddenException("Attempt from {} to _all indices for {} and {}", request.remoteAddress(), action, user));
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

            eval = evaluator.getEvaluator(ci, aliases, types, resolvedAddress, user);

            request.putInContext("armor_ac_evaluator", eval);

            copyContextToHeader(request);
        } else {
            eval = request.getFromContext("armor_ac_evaluator");
        }

        final List<String> filter = request.getFromContext("armor_filter", Collections.EMPTY_LIST);

        log.trace("filter {}", filter);

        for (int i = 0; i < filter.size(); i++) {
            final String[] f = filter.get(i).split(":");
            final String ft = f[0];
            final String fn = f[1];

            log.trace("Filter {}. {}/{}", i, ft, fn);

            if (ft.contains("dlsfilter") || ft.contains("flsfilter")) {
                log.trace("    {} skipped here", ft);
                continue;
            }

            final FilterAction faction = eval.evaluateFilter(ft, fn);

            if (faction == FilterAction.BYPASS) {
                log.trace("will bypass");
                continue;
            }

            if ("actionrequestfilter".equals(ft)) {

                final List<String> allowedActions = request.getFromContext("armor." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("armor." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, forbiddenAction, false)) {

                        log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, forbiddenAction);
                        auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);
                        listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction));
                        throw new ForbiddenException("Action '{}' is forbidden due to {}", action, forbiddenAction);
                    }
                }

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(action, allowedAction, false)) {
                        log.trace("Action '{}' is allowed due to {}", action, allowedAction);
                        chain.proceed(task, action, request, listener);
                        return;
                    }
                }

                log.warn("{}.{} Action '{}' is forbidden due to {}", ft, fn, action, "DEFAULT");
                auditListener.onMissingPrivileges(user == null ? "unknown" : user.getName(), request);

                listener.onFailure(new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action));
                throw new ForbiddenException("Action '{}' is forbidden due to DEFAULT", action);
            }

            if ("restactionfilter".equals(ft)) {
                final String simpleClassName = request.getFromContext("armor." + ft + "." + fn + ".class_name", null);

                final List<String> allowedActions = request.getFromContext("armor." + ft + "." + fn + ".allowed_actions",
                        Collections.EMPTY_LIST);
                final List<String> forbiddenActions = request.getFromContext("armor." + ft + "." + fn + ".forbidden_actions",
                        Collections.EMPTY_LIST);

                for (final Iterator<String> iterator = forbiddenActions.iterator(); iterator.hasNext();) {
                    final String forbiddenAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, forbiddenAction, false)) {
                        throw new RuntimeException("[" + ft + "." + fn + "] Forbidden action " + simpleClassName + " . Allowed actions: "
                                + allowedActions);

                    }
                }

                boolean passall = false;

                for (final Iterator<String> iterator = allowedActions.iterator(); iterator.hasNext();) {
                    final String allowedAction = iterator.next();
                    if (SecurityUtil.isWildcardMatch(simpleClassName, allowedAction, false)) {
                        passall = true;
                        break;
                    }
                }

                if (!passall) {
                    throw new ForbiddenException("Forbidden action {} . Allowed actions: {}", simpleClassName, allowedActions);
                }

            }

            //DLS/FLS stuff is not done here, its done on SearchCallback
        }

        chain.proceed(task, action, request, listener);

    }

    @Override
    public void apply(final String action, final ActionResponse response, final ActionListener listener, final ActionFilterChain chain) {
        chain.proceed(action, response, listener);
    }

    //works also with alias of an alias!
    private List<String> resolveAliases(final List<String> indices) {

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

    private List<String> getOnlyAliases(final List<String> indices) {

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

    private void addType(final IndicesRequest request, final List<String> typesl, final String action) {

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
