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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.searchbox.client.JestClient;
import io.searchbox.client.JestResult;
import io.searchbox.indices.mapping.PutMapping;
import org.apache.http.HttpResponse;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.util.Map;

public class MiscTest extends AbstractUnitTest {

    @Test
    public void checkDLSFLS() throws Exception {
        Assert.assertTrue(ArmorPlugin.DLS_SUPPORTED);
    }

    @Test
    public void unauthenticatedTest() throws Exception {

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.restactionfilter.names", "readonly")
                .putArray("armor.restactionfilter.readonly.allowed_actions", "*")
                .put("armor.authentication.http_authenticator.impl",
                        "com.petalmd.armor.authentication.http.HTTPUnauthenticatedAuthenticator")
                .put("armor.authentication.authentication_backend.impl",
                        "com.petalmd.armor.authentication.backend.simple.AlwaysSucceedAuthenticationBackend")

                .build();

        startES(settings);

        username = null;
        password = null;

        setupTestData("ac_rules_3.json");
        final Tuple<JestResult, HttpResponse> resulttu = executeSearch("ac_query_matchall.json", new String[] { "internal" }, null, true,
                false);

        final JestResult result = resulttu.v1();

        final Gson gson = new GsonBuilder().setPrettyPrinting().create();
        final Map json = gson.fromJson(result.getJsonString(), Map.class);
        log.debug(gson.toJson(json));

    }

    @Test
    public void testArmorIndexAttack() throws Exception {

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.authentication.authorization.settingsdb.roles.jacksonm", "root")
                .put("armor.authentication.settingsdb.user.jacksonm", "secret")
                .put("armor.authentication.authorizer.impl",
                        "com.petalmd.armor.authorization.simple.SettingsBasedAuthorizator")
                        .put("armor.authentication.authorizer.cache.enable", "true")
                        .put("armor.authentication.authentication_backend.impl",
                                "com.petalmd.armor.authentication.backend.simple.SettingsBasedAuthenticationBackend")
                .put("armor.authentication.authentication_backend.cache.enable", "true")

                .putArray("armor.restactionfilter.names", "readonly")
                                .putArray("armor.restactionfilter.readonly.allowed_actions", "RestSearchAction").build();

        startES(settings);
        username = "jacksonm";
        password = "secret";
        setupTestData("ac_rules_1.json");
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", false, false);
        executeIndex("ac_rules_1.json", "armor", "ac", "ac", true, true);
        executeIndex("ac_rules_1.json", "armor", "xx", "xx", false, false);

        final JestClient client = getJestClient(getServerUri(false), username, password);

        final JestResult jr = client.execute(new PutMapping.Builder("_all", "ac", "{" + "\"properties\" : {"
                + "\"rules\" : {\"type\" : \"string\", \"store\" : true }" + "}" + "}"

        ).setHeader(headers).build());

        Assert.assertNotNull(jr.getErrorMessage());
        log.debug(jr.getErrorMessage());
        Assert.assertTrue(jr.getErrorMessage().contains("to _all indices"));

    }
}
