osmo-smdpp
==========

`osmo-smdpp` is a proof-of-concept implementation of a minimal **SM-DP+** as specified for the *GSMA
Consumer eSIM Remote SIM provisioning*.

At least at this point, it is intended to be used for research and development, and not as a
production SM-DP+.

Unless you are a GSMA SAS-SM accredited SM-DP+ operator and have related DPtls, DPauth and DPpb
certificates signed by the GSMA CI, you **can not use osmo-smdpp with regular production eUICC**.
This is due to how the GSMA eSIM security architecture works.  You can, however, use osmo-smdpp with
so-called *test-eUICC*, which contain certificates/keys signed by GSMA test certificates as laid out
in GSMA SGP.26.

At this point, osmo-smdpp does not support anything beyond the bare minimum required to download
eSIM profiles to an eUICC.  Specifically, there is no ES2+ interface, and there is no built-in
support for profile personalization yet.

osmo-smdpp currently

* always provides the exact same profile to every request.  The profile always has the same IMSI and
  ICCID.
* **is absolutely insecure**, as it

 * does not perform any certificate verification
 * does not evaluate/consider any *Matching ID* or *Confirmation Code*
 * stores the sessions in an unencrypted _python shelve_ and is hence leaking one-time key materials
   used for profile encryption and signing.


Running osmo-smdpp
------------------

osmo-smdpp does not have built-in TLS support as the used *twisted* framework appears to have
problems when using the example elliptic curve certificates (both NIST and Brainpool) from GSMA.

So in order to use it, you have to put it behind a TLS reverse proxy, which terminates the ES9+
HTTPS from the LPA, and then forwards it as plain HTTP to osmo-smdpp.

nginx as TLS proxy
~~~~~~~~~~~~~~~~~~

If you use `nginx` as web server, you can use the following configuration snippet::

  upstream smdpp {
          server localhost:8000;
  }

  server {
          listen 443 ssl;
          server_name testsmdpplus1.example.com;

          ssl_certificate /my/path/to/pysim/smdpp-data/certs/DPtls/CERT_S_SM_DP_TLS_NIST.pem;
          ssl_certificate_key /my/path/to/pysim/smdpp-data/certs/DPtls/SK_S_SM_DP_TLS_NIST.pem;

          location / {
                  proxy_read_timeout 600s;

                  proxy_hide_header X-Powered-By;
                  proxy_set_header X-Real-IP $remote_addr;
                  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                  proxy_set_header X-Forwarded-Proto https;
                  proxy_set_header X-Forwarded-Port $proxy_port;
                  proxy_set_header Host $host;

                  proxy_pass http://smdpp/;
          }
  }

You can of course achieve a similar functionality with apache, lighttpd or many other web server
software.


osmo-smdpp
~~~~~~~~~~

osmo-smdpp currently doesn't have any configuration file or command line options.  You just run it,
and it will bind its plain-HTTP ES9+ interface to local TCP port 8000.

The `smdpp-data/certs`` directory contains the DPtls, DPauth and DPpb as well as CI certificates
used; they are copied from GSMA SGP.26 v2.

The `smdpp-data/upp` directory contains the UPP (Unprotected Profile Package) used.


DNS setup for your LPA
~~~~~~~~~~~~~~~~~~~~~~

The LPA must resolve `testsmdpplus1.example.com` to the IP address of your TLS proxy.

It must also accept the TLS certificates used by your TLS proxy.

