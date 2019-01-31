# cics-java-liberty-jaspic-jwt
Sample implementation of Java Authentication Service Provider Interface for Containers (JASPIC) for use with CICS Liberty to validate [JSON web tokens (JWTs)](https://tools.ietf.org/html/rfc7519). This implementation relies on the Liberty JWT feature to validate the token and set the authenticated user ID and the groups to which he belongs based on the JWT claims. This JASPIC implementation will be deployed as a Liberty user feature.

## Introduction

There are different ways to configure a Liberty server to integrate with third-party security services. One of these is the use of a JASPIC implementation. JASPIC is a programming model, its specifications can be found on the [Java Community Process](http://www.jcp.org/en/jsr/detail?id=196). It defines a Service Provider Interface (SPI) by which third-party security providers that implement message authentication mechanisms can be integrated into the web server.

The current JASPIC implementation aims at providing an authentication mechanism based on the validation of JWTs.

> Note: The use of a JASPIC should be handled with care, where possible use a standard supported mechanism within Liberty to achieve security architecture and integration goals. For instance, the validation of a JWT can be achieved by using built-in process in Liberty stand-alone v16.0.0.3 and later versions.

This sample class provides the following functions:

* JWT validation based on the JWTConsumer API (Liberty JWT feature) - the JWT signature will be checked, and the claims (exp, iss, aud) will be validated against the expected values;

* Assign the ***Principal*** identity by retrieving the ***subject*** claim;

* Assign the ***Groups***, to which the Principal belongs, by retrieving the ***groupIds*** claim;

## How does it work?

When the Liberty server is launched, it will read the *jwtConsumer* configuration named `myJWTConsumer`, which is defined in server.xml, and make it available. The myJWTJaspicService-1.0 user feature will be activated, and the implemented JWT message authentication mechanism will be used.

The _com.ibm.cicsdev.jaspic.jwt_ Java package contains the necessary Java classes to comply with the JASPIC model:
* *JWTJaspiProviderService* implements *ProviderService*, it returns an instance of *JWTAuthConfigProvider*;
* *JWTAuthConfigProvider* implements *AuthConfigProvider*, it returns an instance of *JWTServerAuthConfig* to validate the client request;
* *JWTServerAuthConfig* implements *ServerAuthConfig*, it returns an instance of *JWTServerAuthContext*;
* *JWTServerAuthContext* implements *ServerAuthContext*, it uses an instance of *JWTServerAuthModule* to validate the client request;
* *JWTServerAuthModule* implements *ServerAuthModule*, this Java class that does the actual validation of the request;

The *JWTServerAuthModule*'s *validateRequest* method is where the validation of the client HTTP request is done. If the HTTP request does not contain a JWT sent as a **Bearer** token in the Authorization HTTP header, the HTTP request will be rejected.
Otherwise, an instance of *JwtConsumer* is created and loaded with the `myJWTConsumer` configuration. This configuration is defined through a jwtConsumer configuration element in server.xml. The JwtConsumer class is used to validate and parse JWTs.

If the JWT is invalid (wrong claims, expired token, wrong signature, etc.), a Java Exception will be thrown. Otherwise, the user existence is checked against the user registry.
If the user exists, the subject claim will be set as the Principal, and the groupIds claim will be set as the Groups.

This sample shows how a JASPIC implementation can handle a simple JWT use case.

## Generate the ESA file for the Liberty feature 

### Import the Eclipse projects
1. Download the Git repository as an archive.
2. Launch IBM Explorer for z/OS v3.1 or later version, open up the Web perspective
3. In the toolbar select *File* > *Import...* > *Existing Projects into Workspace*.
Then *Select archive file* and *Browse...* to the downloaded archive. 
4. Check the two projects: cics-java-liberty-jaspic-jwt and cics-java-liberty-jaspic-jwt-feature, and finish the import.

### Add missing JAR files
Once imported, the projects may contain compilation errors. To fix these errors, two JAR files have to be added to the target platform environment.
The two required JAR files are to be retrieved from the CICS installation folder:
1. com.ibm.ws.security.jaspic.jar from &lt;cics\_install&gt;/wlp/lib
2. com.ibm.websphere.javaee.jaspic.&lg;version\_number&gt; from &lt;cics\_install&gt;/wlp/dev/api/spec

These files need to be transfered in binary mode from z/OS to the workstation. Do put the JARs file in a new folder.


The target platform needs to be updated:
1. In IBM Explorer, in the toolbar select *Window* > *Preferences* > *Plug-in Development* > *Target Platform*
2. a. If there is no CICS TS target definition, define one by clicking on *Add...*, *Template*, *CICS TS <version> with Java EE and Liberty*, *Next*
   b. Otherwise select the *CICS TS with Java EE and Liberty* target and click on *Edit...*
3. In the *Locations* tab, click on *Add...*, *Directory*, *Next*, *Browse...* to the folder that contains the two JAR files and click *Finish*
4. Click *Finish*
5. Tick the box of the configured *CICS TS with Java EE and Liberty* target and click *OK* to save the target configuration

	
### Export the feature:
1. Go to the Web perspective in IBM Explorer
2. Right-click on the feature project
3. Choose *Export* > *Liberty Feature (ESA)* 
4. Choose where to export the ESA file, the only bundle to include is *com.ibm.cicsdev.jaspic.jwt*
5. Click *Finish*


Upload the generated ESA file (as binary) to the system USS filesystem.

## Installation and Liberty configuration

To install the feature to the Liberty environment, go to the Liberty JVM Server's WLP\_USER\_DIR (this is the folder that contains the *servers* folder). And run:
```
./wlpenv installUtility install <path_to_the_ESA_file>
```
Replace the placeholder with the path to the ESA file.


The command to uninstall is:
```
./wlpenv installUtility uninstall myJWTJaspicService-1.0
```


Then to use the feature, the Liberty server needs to be configured with the following elements:

```xml
<featureManager>
    <feature>cicsts:security-1.0</feature>
    <feature>appSecurity-2.0</feature>
    <feature>jwt-1.0</feature>
    <feature>usr:myJWTJaspicService-1.0</feature>
</featureManager>

<jwtConsumer id="myJWTConsumer" audiences="catalogManager" issuer="idg" signatureAlgorithm="RS256" trustStoreRef="JWTTrustStore" trustedAlias="<certificate_label_or_alias>"/>
<keyStore id="JWTTrustStore" .../>

```

The `jwtConsumer` tag specifies the values that are expected for different claims; update the `audiences` and `issuer` values to match the JWT generator configuration. The tag also specifies which public certificate to use (`trustedAlias`) to validate the JWT signature.
> Note 1: only the public certificate is required, no need to have the private key in the keyStore.

> Note 2: if using a SAF keyring with only a public certificate, do connect the certificate with usage **CERTAUTH**. 

More information on the `trustAssocation` and `interceptors` elements can be found on the [IBM Knowledge Center](https://www.ibm.com/support/knowledgecenter/en/SSEQTP_liberty/com.ibm.websphere.liberty.autogen.base.doc/ae/rwlp_config_trustAssociation.html).<br/>
More information on the `jwtConsumer` element can be found on the [IBM Knowledge Center](https://www.ibm.com/support/knowledgecenter/en/SSEQTP_liberty/com.ibm.websphere.liberty.autogen.base.doc/ae/rwlp_config_jwtConsumer.html).<br/>
More information on the different supported keyStore types on the [IBM Knowledge Center](https://www.ibm.com/support/knowledgecenter/en/SS7K4U_liberty/com.ibm.websphere.wlp.zseries.doc/ae/rwlp_sec_keystores.html).<br/>

## Test

To test the JASPIC implementation, invoke an existing application hosted on your Liberty server that requires authentication. The invokation needs to contain a JWT in the Authorization header. The easiest way to build and send an HTTP request is to use a REST client.<br/>
Make sure to use a JWT that contains the expected claims and to use the right set of public/private keys. If everything goes well you should see that the transaction is run with the user ID provided in the subject claim. Otherwise check the messages.log file.

### Generate a JWT with Liberty

If you don't have a JWT generator at hand, you can use the Liberty server to do it for you.<br/>
Simply add the following `jwtBuilder` tag in the server.xml configuration file:

```xml
<jwtBuilder id="myJWTBuilder" audiences="<audiences_list>" issuer="<issuer_value>" keyAlias="<certificate_label_or_alias>" keyStoreRef="<keyStoreID>"/>
<keyStore id="<keyStoreID>" .../>
```
Replace the placeholders with the correct values.
> Note: This time the keyStore needs to contain the private key in order to sign the JWTs. If the keyStore defined earlier does contain the private key, it can be reused here instead of redefining a new keyStore.

More information on the `jwtBuilder` element on the [IBM Knowledge Center](https://www.ibm.com/support/knowledgecenter/en/SS7K4U_liberty/com.ibm.websphere.liberty.autogen.zos.doc/ae/rwlp_config_jwtBuilder.html).

The JWT feature exposes JWT builders with a REST API. A token can be retrieved by sending the HTTPS request:<br/>
**GET https://&lt;hostname&gt;:&lt;httpsPort&gt;/jwt/ibm/api/myJWTBuilder/token**<br/>
where `myJWTBuilder` is the id used by the configuration.

If the request is sent with a web browser, the browser will prompt for credentials and if the authentication succeeds a JWT will be returned.<br/>
If the request is sent with a REST client, the request needs to contain a Basic Auth header with the credentials.

Once the JWT retrieved, it should be added to the request as an HTTP Authorization header, for instance "Authorization: Bearer &lt;JWT&gt;".

## Reference

For reference information see:
* [Developing a custom JASPIC authentication provider for Liberty](https://www.ibm.com/support/knowledgecenter/en/SS7K4U_liberty/com.ibm.websphere.wlp.zseries.doc/ae/twlp_develop_jaspic.html) for implementation of the Java AuthConfigProvider interface;
* [Configuring a JASPIC User Feature](https://www.ibm.com/support/knowledgecenter/en/SSEQTP_liberty/com.ibm.websphere.wlp.doc/ae/twlp_developing_jaspic_auth_provider.html) for implementation of the JASPIC ProviderService, which uses the AuthConfigProvider object;
* [JASPIC](https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.5.0/applications/developing/java/jaspic_overview.html) for the creation of a user feature; 


## License
This project is licensed under [Apache License Version 2.0](LICENSE).
