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

* [by default] uses test certificates copied from GSMA SGP.26 into `./smdpp-data/certs`, assuming that your
  osmo-smdpp would be running at the host name `testsmdpplus1.example.com`. You can of course replace those
  certificates with your own, whether SGP.26 derived or part of a *private root CA* setup with mathcing eUICCs.
* doesn't understand profile state. Any profile can always be downloaded any number of times, irrespective
  of the EID or whether it was donwloaded before.  This is actually very useful for R&D and testing, as it
  doesn't require you to generate new profiles all the time.  This logic of course is unsuitable for
  production usage.
* doesn't perform any personalization, so the IMSI/ICCID etc. are always identical (the ones that are stored in
  the respective UPP `.der` files)
* **is absolutely insecure**, as it

 * does not perform all of the mandatory certificate verification (it checks the certificate chain, but not
   the expiration dates nor any CRL)
 * does not evaluate/consider any *Confirmation Code*
 * stores the sessions in an unencrypted *python shelve* and is hence leaking one-time key materials
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

supplementary files
~~~~~~~~~~~~~~~~~~~

The `smdpp-data/certs` directory contains the DPtls, DPauth and DPpb as well as CI certificates
used; they are copied from GSMA SGP.26 v2.  You can of course replace them with custom certificates
if you're operating eSIM with a *private root CA*.

The `smdpp-data/upp` directory contains the UPP (Unprotected Profile Package) used.  The file names (without
.der suffix) are looked up by the matchingID parameter from the activation code presented by the LPA.

commandline options
~~~~~~~~~~~~~~~~~~~

Typically, you just run it without any arguments, and it will bind its plain-HTTP ES9+ interface to
`localhost` TCP port 8000.

osmo-smdpp currently doesn't have any configuration file.

There are command line options for binding:

Bind the HTTP ES9+ to a port other than 8000::

  ./osmo-smdpp.py -p 8001

Bind the HTTP ES9+ to a different local interface::

  ./osmo-smdpp.py -H 127.0.0.1

DNS setup for your LPA
~~~~~~~~~~~~~~~~~~~~~~

The LPA must resolve `testsmdpplus1.example.com` to the IP address of your TLS proxy.

It must also accept the TLS certificates used by your TLS proxy.

Supported eUICC
~~~~~~~~~~~~~~~

If you run osmo-smdpp with the included SGP.26 certificates, you must use an eUICC with matching SGP.26
certificates, i.e. the EUM certificate must be signed by a SGP.26 test root CA and the eUICC certificate
in turn must be signed by that SGP.26 EUM certificate.

sysmocom (sponsoring development and maintenance of pySim and osmo-smdpp) is selling SGP.26 test eUICC
as `sysmoEUICC1-C2T`.  They are publicly sold in the `sysmocom webshop <https://shop.sysmocom.de/eUICC-for-consumer-eSIM-RSP-with-SGP.26-Test-Certificates/sysmoEUICC1-C2T>`_.

In general you can use osmo-smdpp also with certificates signed by any other certificate authority.  You
just always must ensure that the certificates of the SM-DP+ are signed by the same root CA as those of your
eUICCs.

Hypothetically, osmo-smdpp could also be operated with GSMA production certificates, but it would require
that somebody brings the code in-line with all the GSMA security requirements (HSM support, ...) and operate
it in a GSMA SAS-SM accredited environment and pays for the related audits.
