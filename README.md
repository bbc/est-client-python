est-client-python
=================

EST client - RFC 7030

```python
import est.client

host = 'testrfc7030.cisco.com'
port = 8443
implicit_trust_anchor_cert_path = 'server.pem'

client = est.client.Client(host, port, implicit_trust_anchor_cert_path)
ca_certs = client.cacerts()

username = 'estuser'
password = 'estpwd'
client.set_basic_auth(username, password)

common_name = 'test'
country = 'US'
state = 'Massachusetts'
city = 'Boston'
organization = 'Cisco Systems'
organizational_unit = 'ENG'
email_address = 'test@cisco.com'
private_key, csr = client.create_csr(common_name, country, state, city,
                                     organization, organizational_unit,
                                     email_address)

client_cert = client.simpleenroll(csr)

client_cert = client.simplereenroll(csr)
```
