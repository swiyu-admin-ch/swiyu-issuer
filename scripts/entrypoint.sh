#!/bin/bash

# Add microservice CAs
echo "Addiing certificates to Java truststore:"
if ls /certs-app/*.crt &> /dev/null; then
    for f in $(ls /certs-app/*.crt); do
        CERT=$f
        CERT_ALIAS=$(basename $CERT .crt)
        echo " => adding $CERT as $CERT_ALIAS to truststore"
        $JAVA_HOME/bin/keytool -importcert -file $CERT -alias $CERT_ALIAS -cacerts -storepass changeit -noprompt -trustcacerts
    done
else
    echo " => No certificates found, skipping"
fi
echo "setting up hsm key"
if [[ -z "${HSM_PRIVATE_KEY}" ]]; then
  echo "No HSM used"
else
  echo "$HSM_PRIVATE_KEY" > /var/usrlocal/luna/config/certs/key.pem
fi

echo "security.provider.13=com.safenetinc.luna.provider.LunaProvider" >> /usr/local/openjdk/conf/security/java.security

java -Duser.timezone=Europe/Zurich \
-Dspring.config.location=classpath:bootstrap.yml,classpath:application.yml,file:/vault/secrets/database-credentials.yml \
-Dfile.encoding=UTF-8 \
-Dspring.profiles.active=${STAGE} \
-Djavax.net.ssl.trustStore=/app/truststore-dev.jks
-Djavax.net.ssl.trustStorePassword=changeit \
-Dhttp.proxyHost=${HTTP_PROXY} \
-Dhttp.proxyPort=8080 \
-Dhttps.proxyHost=${HTTPS_PROXY} \
-Dhttps.proxyPort=8080 \
-Dhttp.nonProxyHosts="${NO_PROXY}" \
-Djava.library.path="/var/usrlocal/luna/jsp/64" \
-cp .:elfa-vz-controller-scs.jar:/var/usrlocal/luna/jsp/LunaProvider.jar \
-Dloader.main=ch.admin.astra.elfa.trotti.Application \
org.springframework.boot.loader.PropertiesLauncher
