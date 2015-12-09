package com.petalmd.armor;

import java.io.IOException;
import java.net.InetAddress;

import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.NoNodeAvailableException;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.junit.Assert;
import org.junit.Test;

import com.petalmd.armor.util.ConfigConstants;
import com.petalmd.armor.util.SecurityUtil;

public class TransportTest extends AbstractUnitTest {

    @Test
    public void sslFail() throws Exception {

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search", "cluster:monitor/health")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                        .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                                SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION, false)

                                .put(getAuthSettings(false, "ceo")).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings.settingsBuilder().put("cluster.name", "armor_testcluster").build();

        final Client tc = new TransportClient.Builder()
                .settings(tsettings)
                .build()
                .addTransportAddress(
                        new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1)
                );
        //final Client tc = new TransportClient.(tsettings).addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"),
        //        elasticsearchNodePort1));

        try {
            waitForGreenClusterState(tc);
            Assert.fail();
        } catch (final Exception e) {
            Assert.assertTrue(e.getClass().toString(), e instanceof NoNodeAvailableException);
        }

        tc.close();
    }

    @Test
    public void ssl() throws Exception {
        final String[] indices = new String[] { "internal" };

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings
                .settingsBuilder()
                .putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search", "cluster:monitor/health")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                        .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                                SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION, false)
                                .put(getAuthSettings(false, "ceo")).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings
                .settingsBuilder()
                .put("cluster.name", "armor_testcluster")
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENABLED, true)
                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_KEYSTORE_FILEPATH,
                        SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorKS.jks"))
                        .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_TRUSTSTORE_FILEPATH,
                                SecurityUtil.getAbsoluteFilePathFromClassPath("ArmorTS.jks"))
                                .put(ConfigConstants.ARMOR_SSL_TRANSPORT_NODE_ENCFORCE_HOSTNAME_VERIFICATION, false).build();

        final Client tc = new TransportClient.Builder()
                .settings(tsettings)
                .build()
                .addTransportAddress(
                        new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1)
                );

        waitForGreenClusterState(tc);

        final SearchRequest sr = new SearchRequest(indices).source(loadFile("ac_query_matchall.json"));
        sr.putHeader("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");

        final SearchResponse response = tc.search(sr).actionGet();
        assertSearchResult(response, 7);

        tc.close();
    }

    @Test
    public void dls() throws Exception {

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings.settingsBuilder().putArray("armor.dlsfilter.names", "dummy2-only")
                .putArray("armor.dlsfilter.dummy2-only", "term", "user", "umberto", "true")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true).put(getAuthSettings(false, "ceo")).build();

        startES(settings);

        setupTestData("ac_rules_execute_all.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings.settingsBuilder().put("cluster.name", "armor_testcluster").build();

        final Client tc = new TransportClient.Builder()
                .settings(tsettings)
                .build()
                .addTransportAddress(
                        new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1)
                );

        waitForGreenClusterState(tc);

        final SearchRequest sr = new SearchRequest(new String[] { "ceo", "future" }).source(loadFile("ac_query_matchall.json"));
        sr.putHeader("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");

        final SearchResponse response = tc.search(sr).actionGet();
        assertSearchResult(response, 2);

        tc.close();
    }

    protected final Client newTransportClient() throws IOException {
        final Settings tsettings = Settings.settingsBuilder().put("cluster.name", "armor_testcluster").build();

        final Client tc = new TransportClient.Builder()
                .settings(tsettings)
                .build()
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1))
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort2))
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort3));


        waitForGreenClusterState(tc);
        return tc;
    }

    @Test
    public void searchOnlyAllowed() throws Exception {
        final String[] indices = new String[] { "internal" };

        username = "jacksonm";
        password = "secret";

        final Settings settings = Settings.settingsBuilder().putArray("armor.actionrequestfilter.names", "readonly")
                .putArray("armor.actionrequestfilter.readonly.allowed_actions", "indices:data/read/search")
                .put(ConfigConstants.ARMOR_TRANSPORT_AUTH_ENABLED, true).put(ConfigConstants.ARMOR_AUDITLOG_ENABLED, false)
                .put(getAuthSettings(false, "ceo")).build();

        startES(settings);

        setupTestData("ac_rules_1.json");

        log.debug("------------------------------------------------------------------------------------------------------------------------------------------------------------------------");

        final Settings tsettings = Settings.settingsBuilder().put("cluster.name", "armor_testcluster").build();

        final Client tc = new TransportClient.Builder()
                .settings(tsettings)
                .build()
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort1))
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort2))
                .addTransportAddress(new InetSocketTransportAddress(InetAddress.getByName("127.0.0.1"), elasticsearchNodePort3));

        waitForGreenClusterState(tc);

        final SearchRequest sr = new SearchRequest(indices).source(loadFile("ac_query_matchall.json"));
        sr.putHeader("armor_transport_creds", "amFja3Nvbm06c2VjcmV0");

        final SearchResponse response = tc.search(sr).actionGet();
        assertSearchResult(response, 7);
//
//        try {
//            final GetResponse getResponse = newTransportClient().get(
//                    (GetRequest) new GetRequest(indices[0], "test", "dummy").putHeader("armor_transport_creds",
//                            "amFja3Nvbm06c2VjcmV0")).actionGet();
//            Assert.fail();
//        } catch (final ForbiddenException e) {
//            //exp Forbidden exception
//        }
//
//        try {
//            final IndexResponse indexResponse = tc.index(
//                    (IndexRequest) new IndexRequest(indices[0], "test").source("{}").putHeader("armor_transport_creds",
//                            "amFja3Nvbm06c2VjcmV0")).actionGet();
//            Assert.fail();
//        } catch (final ForbiddenException e) {
//            //exp Forbidden exception
//        }
//
//        try {
//            final IndexResponse indexResponse = tc.index(new IndexRequest(indices[0], "test").source("{}")).actionGet();
//            Assert.fail();
//        } catch (final RuntimeException e) {
//            Assert.assertTrue(e.getCause().getMessage(), e.getCause().getMessage().contains("Unauthenticated request"));
//        }
//
//        response = tc.search(
//                (SearchRequest) new SearchRequest(indices).source(loadFile("ac_query_matchall.json")).putHeader(
//                        "armor_authenticated_transport_request",
//                        SecurityUtil.encryptAndSerializeObject("authorized", ArmorService.getSecretKey()))).actionGet();
//        assertSearchResult(response, 7);
//
//        //Dummy key
//        final SecureRandom secRandom = SecureRandom.getInstance("SHA1PRNG");
//        final KeyGenerator kg = KeyGenerator.getInstance("AES");
//        kg.init(128, secRandom);
//        final SecretKey dummyKey = kg.generateKey();
//
//        try {
//            response = tc.search(
//                    (SearchRequest) new SearchRequest(indices).source(loadFile("ac_query_matchall.json")).putHeader(
//                            "armor_authenticated_transport_request", SecurityUtil.encryptAndSerializeObject("authorized", dummyKey)))
//                            .actionGet();
//            Assert.fail();
//        } catch (final Exception e) {
//            Assert.assertTrue(e.getClass().toString(), e instanceof ElasticsearchException);
//            Assert.assertTrue(e.getMessage(), e.getMessage().contains("Given final block not properly padded"));
//        }

        tc.close();
    }

    protected void assertSearchResult(final SearchResponse response, final int count) {
        Assert.assertNotNull(response);
        Assert.assertEquals(0, response.getFailedShards());
        Assert.assertEquals(count, response.getHits().getTotalHits());
        Assert.assertFalse(response.isTimedOut());
    }
}
