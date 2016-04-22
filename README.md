# A.R.M.O.R Security Plugin for ES 2.1
Elasticsearch security for free.

ARMOR is a free and open source plugin for Elasticsearch which provides security features.

[![Build Status](https://travis-ci.org/petaldevelopment/armor.svg)](https://travis-ci.org/petaldevelopment/armor)
[![Coverage Status](https://coveralls.io/repos/petaldevelopment/armor/badge.svg?branch=master&service=github)](https://coveralls.io/github/petaldevelopment/armor?branch=master)
[![Dependency Status](https://www.versioneye.com/user/projects/562ebc6f36d0ab001600165d/badge.svg?style=flat)](https://www.versioneye.com/user/projects/562ebc6f36d0ab001600165d)
[![License](http://img.shields.io/:license-apache--2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

## Features
* Flexible REST layer access control (User/Role based; on aliases, indices and types)
* Flexible transport layer access control (User/Role based; on aliases, indices and types)
* Document level security (DLS): Retrieve only documents matching criterias
* Field level security (FLS): Filter out fields/sourceparts from a search response
* HTTP authentication (Basic, Proxy header, SPNEGO/Kerberos, Mutual SSL/CLIENT-CERT)
* HTTP session support through cookies
* Flexible authentication backends (LDAP(s)/Active Directory, File based, Proxy header, Native Windows through WAFFLE)
* Flexible authorization backends (LDAP(s)/Active Directory, File based, Native Windows through WAFFLE)
* [Node-to-node encryption through SSL/TLS (Transport layer)](/docs/encryption.md)
* [Secure REST layer through HTTPS (SSL/TLS)](/docs/encryption.md)
* X-Forwarded-For (XFF) support
* Audit logging
* Anonymous login/unauthenticated access
* Works with Kibana 4 and logstash

## Limitations
* When using DLS or FLS you can still search in all documents/fields but not all documents/fields are returned
* Transport layer access control only with simple username/password login
* No automatic multi index filters (see below)
* Currently monitoring of the cluster needs no authentication and is allowed always (this may change in the future)

## How it works
Basically ARMOR consists of an authentication, authorization, SSL/TLS, XFF, HTTP session and audit log module and access control. All of them without the exception of access control are more or less self-explanatory. But access control, the heart of ARMOR, needs some more attention.

ARMOR has the concept of routing a request through a chain of filters which can modify or block the request/response. There are currently 3 types of filters:

* **actionrequest/restrequest filter**: Checks if the user is allowed to perform actions (like read, write, admin actions …). Works generally, not only for search requests.
* **dls filter**: filters out documents from the search response
* **fls filter**: filter out fields from the documents of a search response

## Pre-Installation
### Check Release Integrity

You **must** verify the integrity of the downloaded files. We provide PGP signatures for every release file. This signature should be matched against the KEYS file. We also provide MD5 and SHA-1 checksums for every release file. After you download the file, you should calculate a checksum for your download, and make sure it is the same as ours. [Here](http://www.openoffice.org/download/checksums.html) and [here](https://www.apache.org/info/verification.html) are some tips how to verify the pgp signatures.

### Setup ACL rules

It's recommended to setup the access control rules (ACL rules) **before** installing the plugin to simplify the installation process.
If you install the plugin first you have to do extra effort cause then your're firstly locked-out of elasticsearch.

Why not install a ACL rules file which grants _all access_ for a user with role _admin_?

```
curl -XPUT 'http://localhost:9200/armor/ac/ac' -d '{
    "acl": [
    {
        "__Comment__": "By default no filters are executed and no filters a by-passed. In such a case an exception is thrown and access will be denied.",
        "filters_bypass": [],
        "filters_execute": []
     },
     {
           "__Comment__": "For role *admin* all filters are bypassed (so none will be executed). This means unrestricted access.",
           "roles": [
               "admin"
           ],
           "filters_bypass": ["*"],
           "filters_execute": []
     }
     ]
}'
```

## Installation
Install it like any other Elasticsearch plugin:
(On Centos, you can find the `bin/plugin` at `/usr/share/elasticsearch`)

```
# ES 2.1
$ bin/plugin -i com.petalmd/armor/2.1.0
```

Prerequisites:

* Java 7 or 8 (recommended)
* Elasticsearch 2.1.x

Build it yourself:
* Install maven 3.1+
* ``git clone https://github.com/petaldevelopment/armor.git`
* ``cd armor``
* execute ``mvn package -DskipTests``


## Configuration

### Logging
Configured in elasticsearch's logging.yml. Nothing special. To enable debug just add

``logger.com.petaldevelopment: DEBUG``


### Keys
Two kind of keys are used by ARMOR:
* ARMOR node key (armor_node.key)
 * This is a key which generated and saved to disk by the plugin if a node starts up (and key is not already present)
 * Its used to secure node communication even if no SSL/TLS is configured
 * Every node in the cluster has to use the same key file (armor_node.key)
 * It's recommended to let one node generate a file and copy this (securely) to every node in the cluster
* Optionally SSL keys (certificates)
 * If you want to use SSL/TLS see [example-pki-scripts](example-pki-scripts) how to generate the certificates. It's strongly recommended to use a root certificate.</a>
 * See https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores
 * or https://tomcat.apache.org/tomcat-8.0-doc/ssl-howto.html

### ACL rules (stored in Elasticsearch itself)
The security rules for each module are stored in an special index `armor` and with a type and id of `ac`.

See below (or look at chapter **Pre-Installation**) for more details.

### AuthN & AuthZ in elasticsearch.yml
See [armor_config_template.yml](armor_config_template.yml). Just copy the content over to elasticsearch.yml and modify the settings so fit your needs. A very basic example you can find [here](armor_config_example_1.yml)

####Within elasticsearch.yml you configure

* Global options for armor
* HTTP/REST SSL/TLS
* Transport SSL/TLS
* HTTP authentication method
 * Basic, SPNEGO, Client-Cert, Proxy header, WAFFLE (NTLM), ...
* Authentication backend
 * LDAP, File based, Always authenticate
* Authorization backend
 * LDAP, WAFFLE (AD), File based
* Security Filters (see next section)

#### Security Filters
All the configuration up to know makes only sense if we can limit the usage of Elasticsearch for the authenticated user.
There are four types of security filters (by now) which also can be used together.

* **restactionfilter**: Limit Elasticsearch actions by type of rest actions which are allowed (or forbidden)
* **actionrequestfilter**: Limit Elasticsearch actions by type request actions which are allowed (or forbidden)
* **dlsfilter**: Only return documents which match defined criterias
* **flsfilter**: Filter document source and exclude (or include) fields

You have to configure at least on filter.

### On which nodes the plugin needs to be installed
If you use either transport layer SSL or DLS or FLS you have to install it on every node. Otherwise install it on every client node which is exposed to be the entry point into the cluster and on every node which exposes the HTTP REST API. Please note that the ``armor.config_index_name`` must be the same for all nodes in within a cluster.

### Auditlog
Auditlog is stored in Elasticsearch within the _armor_ index (with type _audit_)

```
$ curl -XGET 'http://localhost:9200/armor/audit/_search?pretty=true'
```

### Rules evaluation
Now lets define for which user on which index which filter have to be applied.

```json
{
  "acl": [
    {
      "__Comment__": "By default no filters are executed and no filters a by-passed. In such a case a exception is throws an access will be denied.",
      "filters_bypass": [],
      "filters_execute": []
    },
    {
      "__Comment__": "For admin role all filters are bypassed (so none will be executed) for all indices. This means unrestricted access at all for this role.",
      "roles": ["admin"],
      "filters_bypass": ["*"],
      "filters_execute": []
    },
    {
      "__Comment__": "For every authenticated user who access the index 'public' for this access all non dls and all non fls filters are executed.",
      "indices": ["public"],
      "filters_bypass": [
        "dlsfilter.*",
        "dlsfilter.*"
      ],
      "filters_execute": ["*"]
    },
    {
      "__Comment__": "For marketing role all filters are bypassed (so none will be executed) for index 'marketing'. This means unrestricted access to this index for this role.",
      "roles": ["marketing"],
      "indices": ["marketing"],
      "filters_bypass": ["*"],
      "filters_execute": []
    },
    {
      "__Comment__": "For finance role all filters are bypassed (so none will be executed) for index 'finance'. This means unrestricted access to this index for this role.",
      "roles": ["finance"],
      "indices": ["financ*"],
      "filters_bypass": ["*"],
      "filters_execute": []
    },
    {
      "__Comment__": "For marketing role the filters 'flsfilter.filter_sensitive_finance' and 'actionrequestfilter.readonly' are executed (but no other filters) for index 'finance'",
      "roles": ["marketing"],
      "indices": ["financ*"],
      "filters_bypass": [],
      "filters_execute": [
        "flsfilter.filter_sensitive_fina*",
        "actionrequestfilter.readonly"
      ]
    },
    {
      "__Comment__": "For roles 'ceo' 'marketing' 'finance' all filters are bypassed (so none will be executed) for alias 'planning'. This means unrestricted access to this alias for this roles.",
      "roles": [
        "ce*o",
        "marke*ing",
        "*nanc*"
      ],
      "aliases": ["planning"],
      "filters_bypass": ["*"],
      "filters_execute": []
    },
    {
      "__Comment__": "For finance role the filters 'dlsfilter.filter_sensite_from_ceodata' and 'actionrequestfilter.readonly' are executed (but no other filters) for index 'ceodata'",
      "roles": ["finance"],
      "indices": ["ceodat*"],
      "filters_bypass": [],
      "filters_execute": [
        "dlsfilter.filter_sensitive_from_ceodata",
        "actionrequestfilter.readonly"
      ]
    },
    {
      "__Comment__": "For role 'ceo' all filters are bypassed (so none will be executed) for index 'ceodata'. This means unrestricted access to this index for this role.",
      "roles": ["ce*o"],
      "indices": ["ceodata"],
      "filters_bypass": ["*"],
      "filters_execute": []
    }
   ]
}
```

For every rule that match all execute and bypass filters will be concatenated, and **bypass** is winning over **execute**.
For example if an user which has the roles _marketing_ and _finance_ and want to access index _marketing_ the final result looks like

```yaml
filters_bypass=["*"],
filters_execute=["flsfilter.filter_sensitive_fina*","actionrequestfilter.readonly"]
```
which then will be resolved to ``filters_bypass= ["*"]`` (execute **NO** filter at all).
Because bypass is winning.


If a user which has the _marketing_ role and want to access index _finance_ the final result looks like

```yaml
filters_bypass: []
filters_execute: ["flsfilter.filter_sensitive_fina*", "actionrequestfilter.readonly"]
```
which then will be resolved to

```yaml
filters_execute: ["flsfilter.filter_sensitive_fina*", "actionrequestfilter.readonly"]
```
(execute these two filters, no others).

For an admin accessing index _public_ it looks like

```yaml
filters_bypass: ["*", "dls.*", "fls.*"],
filters_execute: ["*"]
```

which then will be resolved to `filters_bypass: ["*"]` (execute **NO** filter at all).
Because bypass is winning.

If filters resolve to

```yaml
  filters_bypass: []
  filters_execute:  []
```
then an security exception will be thrown.



For the sake of completeness a rule definition can look like:

```js
{
        // who is the requestor
        "hosts":[
           "10.*.1.*",
           "host-*.company.org"
        ],
        "users":["*"],
        "roles":["*"],

        // on what resources do the requestor operate
        "indices":["public"],
        "aliases":["..."],

        // which filters have to be applied or can be bypassed for this
        // requestor on this resource
        "filters_bypass": ["*"],
        "filters_execute": []
}
```
Everywhere a simple wildcard (*) can be used.

To make the rule apply all present attributes (users, roles, hosts, indices, aliases) must match. An attribute which is missing or is empty does always match. An attribute only containing the wildcard sign (*) does also match always.

#### No automatic multi index filters
If you access more than one index (e.g. search in multiple indices) only rules will match when they list all the indices (or "*”). So for a multi index search on the indices _marketing_ and _finance_ a rules have to look like:

```json
{
    "roles": ["..."],
    "indices": [
         "finance",
         "marketing"
    ],
    "filters_bypass": ["..."],
    "filters_execute": ["..."]
}
```
You can circumvent this by using aliases.

## Integration
### Kibana
See the documentation for [Kibana 4.2](/docs/kibana.md)

## Roadmap
TODO

## Community
Contributions, questions, and comments are all welcomed and encouraged!

## License
This project derives from [Search-guard 1.6](https://github.com/floragunncom/search-guard)

Copyright 2015 PetalMD

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   `http://www.apache.org/licenses/LICENSE-2.0`

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
