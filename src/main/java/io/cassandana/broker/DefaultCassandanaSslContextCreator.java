/*
 *  Copyright 2019 Mohammad Taqi Soleimani
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package io.cassandana.broker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import io.cassandana.broker.config.Config;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Cassandana integration implementation to load SSL certificate from local filesystem path configured in
 * config file.
 */
class DefaultCassandanaSslContextCreator implements ISslContextCreator {

    private final Config conf;

    DefaultCassandanaSslContextCreator(Config conf) {
    	this.conf = conf;
//        this.props = Objects.requireNonNull(props);
    }

    @Override
    public SslContext initSSLContext() {
        final String keyPassword = conf.certKeyManagerPassword;// props.getProperty(BrokerConstants.KEY_MANAGER_PASSWORD_PROPERTY_NAME);
        if (keyPassword == null || keyPassword.isEmpty()) {
            return null;
        }

        try {
            SslProvider sslProvider = getSSLProvider();
            KeyStore ks = loadKeyStore();
            SslContextBuilder contextBuilder;
            switch (sslProvider) {
            case JDK:
                contextBuilder = builderWithJdkProvider(ks, keyPassword);
                break;
            case OPENSSL:
            case OPENSSL_REFCNT:
                contextBuilder = builderWithOpenSSLProvider(ks, keyPassword);
                break;
            default:
                return null;
            }
            // if client authentification is enabled a trustmanager needs to be added to the ServerContext
            /*String sNeedsClientAuth = props.getProperty(BrokerConstants.NEED_CLIENT_AUTH, "false");
            if (Boolean.valueOf(sNeedsClientAuth)) {
                addClientAuthentication(ks, contextBuilder);
            }*/
            if(conf.certClientAuth) {
            	addClientAuthentication(ks, contextBuilder);
            }
            
            contextBuilder.sslProvider(sslProvider);
            SslContext sslContext = contextBuilder.build();
            return sslContext;
        } catch (GeneralSecurityException | IOException ex) {
            return null;
        }
    }

    private KeyStore loadKeyStore() throws IOException, GeneralSecurityException {
        final String jksPath = conf.certPath;// props.getProperty(BrokerConstants.JKS_PATH_PROPERTY_NAME);
        if (jksPath == null || jksPath.isEmpty()) {
            return null;
        }
        final String keyStorePassword = conf.certKeyStorePassword;//  props.getProperty(BrokerConstants.KEY_STORE_PASSWORD_PROPERTY_NAME);
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            return null;
        }
        String ksType = conf.certKeyStoreType;// props.getProperty(BrokerConstants.KEY_STORE_TYPE, "jks");
        final KeyStore keyStore = KeyStore.getInstance(ksType);
        try (InputStream jksInputStream = jksDatastore(jksPath)) {
            keyStore.load(jksInputStream, keyStorePassword.toCharArray());
        }
        return keyStore;
    }

    private static SslContextBuilder builderWithJdkProvider(KeyStore ks, String keyPassword)
            throws GeneralSecurityException {
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPassword.toCharArray());
        return SslContextBuilder.forServer(kmf);
    }

    /**
     * The OpenSSL provider does not support the {@link KeyManagerFactory}, so we have to lookup the integration
     * certificate and key in order to provide it to OpenSSL.
     * <p>
     * TODO: SNI is currently not supported, we use only the first found private key.
     */
    private static SslContextBuilder builderWithOpenSSLProvider(KeyStore ks, String keyPassword)
            throws GeneralSecurityException {
        for (String alias : Collections.list(ks.aliases())) {
            if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                PrivateKey key = (PrivateKey) ks.getKey(alias, keyPassword.toCharArray());
                Certificate[] chain = ks.getCertificateChain(alias);
                X509Certificate[] certChain = new X509Certificate[chain.length];
                System.arraycopy(chain, 0, certChain, 0, chain.length);
                return SslContextBuilder.forServer(key, certChain);
            }
        }
        throw new KeyManagementException("the SSL key-store does not contain a private key");
    }

    private static void addClientAuthentication(KeyStore ks, SslContextBuilder contextBuilder)
            throws NoSuchAlgorithmException, KeyStoreException {
        // use keystore as truststore, as integration needs to trust certificates signed by the integration certificates
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        contextBuilder.clientAuth(ClientAuth.REQUIRE);
        contextBuilder.trustManager(tmf);
    }

    private SslProvider getSSLProvider() {
        String providerName = conf.certProvider;// props.getProperty(BrokerConstants.SSL_PROVIDER, SslProvider.JDK.name());
        try {
            return SslProvider.valueOf(providerName);
        } catch (IllegalArgumentException e) {
            return SslProvider.JDK;
        }
    }

    private InputStream jksDatastore(String jksPath) throws FileNotFoundException {
        URL jksUrl = getClass().getClassLoader().getResource(jksPath);
        if (jksUrl != null) {
            return getClass().getClassLoader().getResourceAsStream(jksPath);
        }
        File jksFile = new File(jksPath);
        if (jksFile.exists()) {
            return new FileInputStream(jksFile);
        }
        throw new FileNotFoundException("The keystore file does not exist. Url = " + jksFile.getAbsolutePath());
    }
}
