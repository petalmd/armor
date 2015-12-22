# Encryption / Authentification
## Generate Self sign server certificate and add them to truststore
### Generate certificate (keystore.jks) 
```
$ keytool -genkey -alias server_name -keyalg RSA -keypass test123 -storepass test123 -keystore keystore.jks
What is your first and last name?
  []: Julien Maitrehenry
What is the name of your organizational unit?
  []: DevOps
What is the name of your organization?
  []: PetalMD
What is the name of your City or Locality?
  []: Quebec City
What is the name of your State or Province?
  []: QC
What is the two-letter country code for this unit?
  []: CA
Is CN=Julien Maitrehenry, OU=DevOps, O=PetalMD, L=Quebec City, ST=QC, C=CA correct?
  [no]:  yes
```

### Export generated certificate (server.cer)
You can use the same certificate on all node, but having one certificate per node is better and give you opportinity to revoke one without having all node down.

```
$ keytool -export -alias server_name -storepass test123 -file server.cer -keystore keystore.jks
Certificate stored in file <server.cer>
```

### Add certificate to truststore file (cacerts.jks)
You need to add all node certificates on the trust store and install the same truststore on all node.

```
$ keytool -import -v -trustcacerts -alias server_name -file server.cer -keystore cacerts.jks -keypass test123 -storepass test987
Owner: CN=Julien Maitrehenry, OU=DevOps, O=PetalMD, L=Quebec City, ST=QC, C=CA
Issuer: CN=Julien Maitrehenry, OU=DevOps, O=PetalMD, L=Quebec City, ST=QC, C=CA
Serial number: 5927721d
Valid from: Wed Nov 11 14:09:46 EST 2015 until: Tue Feb 09 14:09:46 EST 2016
Certificate fingerprints:
	 MD5:  AE:36:55:E9:85:CE:E9:11:C5:92:C4:8A:ED:77:43:92
	 SHA1: 15:90:6D:DA:91:87:66:F0:61:66:3D:E7:56:99:7C:5E:6A:37:5D:33
	 SHA256: 95:17:8F:91:57:90:4D:95:37:53:6C:6F:52:82:6A:E1:14:CF:DD:72:C6:8B:9A:F0:B5:E0:CC:34:C1:4F:E3:0E
	 Signature algorithm name: SHA256withRSA
	 Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 7B 92 9D E3 77 8C 8F 86   A6 BB 34 3A 39 02 DA DD  ....w.....4:9...
0010: 0E 7C 41 05                                        ..A.
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore
[Storing cacerts.jks]
```

## Node <> node Encryption (transport)
```yaml
# elasticsearch/elasticsearch.yml
#--------------------------------

# Node <> node encryption
armor.ssl.transport.node.enabled: true             # Default true
armor.ssl.transport.node.keystore_type: JKS        # Default JKS
armor.ssl.transport.node.keystore_filepath: /usr/share/elasticsearch/keystore.jks
armor.ssl.transport.node.keystore_password: test123

# Node to Node authentification
armor.ssl.transport.node.enforce_clientauth: false # Default true
armor.ssl.transport.node.truststore_type: JKS      # Default JKS
armor.ssl.transport.node.truststore_filepath: /usr/share/elasticsearch/cacerts.jks
armor.ssl.transport.node.truststore_password: test987

# Hostname verification
armor.ssl.transport.node.encforce_hostname_verification: false # Default true
armor.ssl.transport.node.encforce_hostname_verification.resolve_host_name: false # Default true
```

## Client <> node (REST API)
WIP

```YAML
# elasticsearch/elasticsearch.yml
#--------------------------------
# Client <> Node encryption
armor.ssl.transport.http.enabled: true
```
