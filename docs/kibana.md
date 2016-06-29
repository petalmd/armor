# Kibana and ARMOR setup

## Armor Configuration
All users with Kibana access need to read `.kibana`indice, if the user need to create visualization, dashbord or add indice, he need to write on this indice.

A kibana user must be created with full access to `.kiabana` and don't need access to other indices.

Configuration:

```YAML
# Users
armor.authentication.settingsdb.digest: SHA512
armor.authentication.settingsdb.user.kibana: ABCD1234...
armor.authentication.settingsdb.user.julien: ABCD1234...

# Roles
armor.authentication.authorization.settingsdb.roles.kibana: ["kibana"]
armor.authentication.authorization.settingsdb.roles.julien: ["kibana", "stats_ro"]
```

If you set armor.allow\_kibana\_actions at false and still want to use kibana, you will have to create a filter to authorize the 2 following actions
 -cluster:monitor/health
 -cluster:monitor/nodes/info
 -indices:data/read/field\_stats
 -

```YAML
armor.actionrequestfilter.names: ["defaultfilter", "readwrite"]

armor.actionrequestfilter.defaultfilter.allowed_actions: [
 "cluster:monitor/health",
 "cluster:monitor/nodes/info",
 "indices:data/read/field\_stats"
]

 ...

```

ACL example:

```
curl -XPUT 'http://127.0.0.1:9200/armor/ac/ac?pretty' -d '
{"acl": [
  {
    "__Comment__": "Default filter",
    "filters_bypass": [],
    "filters_execute": ["defaultfilter"]
  },
  {
    "__Comment__": "Internal kibana index",
    "roles": ["kibana"],
    "indices": [".kibana"],
    "filters_bypass": ["*"],
    "filters_execute": []
  },
  {
    "__Comment__": "Analytics data index RO",
    "roles": ["stats_ro"],
    "indices": ["logstash-"],
    "filters_bypass": [],
    "filters_execute": ["armor.actionrequestfilter.readwrite"]
  }
  [...]
]}
```

## Kibana configuration
You need to uncomment `kibana_elasticsearch_username` and `kibana_elasticsearch_password`.
This user will only be use for kibana to start and need access to `.kibana`indice. 
Once a user would like to use Kibana, Kibana will ask for a user/pass and will forward the credential to Elasticsearch.

```YAML
# If your Elasticsearch is protected with basic auth, this is the user credentials
# used by the Kibana server to perform maintence on the kibana_index at statup. Your Kibana
# users will still need to authenticate with Elasticsearch (which is proxied thorugh
# the Kibana server)
kibana_elasticsearch_username: kibana_es_user
kibana_elasticsearch_password: kibana_es_pass
```
