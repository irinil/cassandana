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

import io.cassandana.broker.config.*;
import io.cassandana.broker.security.*;
import io.cassandana.broker.subscriptions.CTrieSubscriptionDirectory;
import io.cassandana.broker.subscriptions.ISubscriptionsDirectory;
import io.cassandana.interception.BrokerInterceptor;
import io.cassandana.interception.InterceptHandler;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.cassandana.persistence.MemorySubscriptionsRepository;

import static io.cassandana.logging.LoggingUtils.getInterceptorIds;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

public class Server {


    private ScheduledExecutorService scheduler;
    private NewNettyAcceptor acceptor;
    private volatile boolean initialized;
    private PostOffice dispatcher;
    private BrokerInterceptor interceptor;
    private SessionRegistry sessions;

    
    public static void main(String[] args) throws Exception {
        final Server server = new Server();
        server.startServer();
        System.out.println("Server started, version 0.1.1-ALPHA");
        //Bind a shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(server::stopServer));
    }

    /**
     * Starts Cassandana bringing the configuration from the file located at ./cassandana.yaml
     * @throws Exception 
     */
    public void startServer() throws Exception {
        startServer(Config.getInstance());
    }


    /**
     * Starts Cassandana bringing the configuration files from the given Config implementation.
     *
     * @param config the configuration to use to start the broker.
     * @throws IOException in case of any IO Error.
     */
    public void startServer(Config config) throws IOException {
        startServer(config, null);
    }

    /**
     * Starts Moquette with config provided by an implementation of IConfig class and with the set
     * of InterceptHandler.
     *
     * @param config   the configuration to use to start the broker.
     * @param handlers the handlers to install in the broker.
     * @throws IOException in case of any IO Error.
     */
    public void startServer(Config config, List<? extends InterceptHandler> handlers) throws IOException {
        startServer(config, handlers, null, null, null);
    }

    public void startServer(Config config, List<? extends InterceptHandler> handlers, ISslContextCreator sslCtxCreator,
                            IAuthenticator authenticator, IAuthorizatorPolicy authorizatorPolicy) throws IOException {
        final long start = System.currentTimeMillis();
        if (handlers == null) {
            handlers = Collections.emptyList();
        }

        scheduler = Executors.newScheduledThreadPool(1);

//        final String handlerProp = System.getProperty(BrokerConstants.INTERCEPT_HANDLER_PROPERTY_NAME);
//        if (handlerProp != null) {
//            config.setProperty(BrokerConstants.INTERCEPT_HANDLER_PROPERTY_NAME, handlerProp);
//        }
        
        initInterceptors(config, handlers);
        if (sslCtxCreator == null) {
            sslCtxCreator = new DefaultCassandanaSslContextCreator(config);
        }
        authenticator = initializeAuthenticator(authenticator, config);
        authorizatorPolicy = initializeAuthorizatorPolicy(authorizatorPolicy, config);

        
        final ISubscriptionsRepository subscriptionsRepository;
        final IQueueRepository queueRepository;
        final IRetainedRepository retainedRepository;
        
        
        subscriptionsRepository = new MemorySubscriptionsRepository();
        queueRepository = new MemoryQueueRepository();
        retainedRepository = new MemoryRetainedRepository();

        
        ISubscriptionsDirectory subscriptions = new CTrieSubscriptionDirectory();
        subscriptions.init(subscriptionsRepository);
        sessions = new SessionRegistry(subscriptions, queueRepository);
        dispatcher = new PostOffice(subscriptions, authorizatorPolicy, retainedRepository, sessions, interceptor);
        final BrokerConfiguration brokerConfig = new BrokerConfiguration(config);
        MQTTConnectionFactory connectionFactory = new MQTTConnectionFactory(brokerConfig, authenticator, sessions,
                                                                            dispatcher);

        final NewNettyMQTTHandler mqttHandler = new NewNettyMQTTHandler(connectionFactory);
        acceptor = new NewNettyAcceptor();
        acceptor.initialize(mqttHandler, config, sslCtxCreator);

        final long startTime = System.currentTimeMillis() - start;
        initialized = true;
    }
    
    private IAuthorizatorPolicy initializeAuthorizatorPolicy(IAuthorizatorPolicy authorizatorPolicy, Config conf) {

        if(conf.aclProvider == SecurityProvider.DENY)
        	return new DenyAllAuthorizatorPolicy();
        else if(conf.aclProvider == SecurityProvider.HTTP)
        	return new HttpAuthorizator(conf);
        else //if(conf.aclProvider == SecurityProvider.PERMIT)
        	return new PermitAllAuthorizatorPolicy();
        
    }

    private IAuthenticator initializeAuthenticator(IAuthenticator authenticator, Config conf) {

        if(conf.authProvider == SecurityProvider.DENY)
        	return new RejectAllAuthenticator();
        else if(conf.authProvider == SecurityProvider.HTTP)
        	return new HttpAuthenticator(conf);
        else //if(conf.aclProvider == SecurityProvider.PERMIT)
        	return new AcceptAllAuthenticator();
        
    }

    private void initInterceptors(Config conf, List<? extends InterceptHandler> embeddedObservers) {

        List<InterceptHandler> observers = new ArrayList<>(embeddedObservers);
        /*String interceptorClassName = props.getProperty(BrokerConstants.INTERCEPT_HANDLER_PROPERTY_NAME);
        if (interceptorClassName != null && !interceptorClassName.isEmpty()) {
            InterceptHandler handler = loadClass(interceptorClassName, InterceptHandler.class,
                                                 io.cassandana.broker.Server.class, this);
            if (handler != null) {
                observers.add(handler);
            }
        }*/
        interceptor = new BrokerInterceptor(conf, observers);
    }


    /**
     * Use the broker to publish a message. It's intended for embedding applications. It can be used
     * only after the integration is correctly started with startServer.
     *
     * @param msg      the message to forward.
     * @param clientId the id of the sending integration.
     * @throws IllegalStateException if the integration is not yet started
     */
    public void internalPublish(MqttPublishMessage msg, final String clientId) {
        final int messageID = msg.variableHeader().packetId();
        if (!initialized) {
            throw new IllegalStateException("Can't publish on a integration is not yet started");
        }
        dispatcher.internalPublish(msg);
    }

    public void stopServer() {
        acceptor.close();
        initialized = false;

        // calling shutdown() does not actually stop tasks that are not cancelled,
        // and SessionsRepository does not stop its tasks. Thus shutdownNow().
        scheduler.shutdownNow();
        

    }

    /**
     * SPI method used by Broker embedded applications to add intercept handlers.
     *
     * @param interceptHandler the handler to add.
     */
    public void addInterceptHandler(InterceptHandler interceptHandler) {
        if (!initialized) {
            throw new IllegalStateException("Can't register interceptors on a integration that is not yet started");
        }
        interceptor.addInterceptHandler(interceptHandler);
    }

    /**
     * SPI method used by Broker embedded applications to remove intercept handlers.
     *
     * @param interceptHandler the handler to remove.
     */
    public void removeInterceptHandler(InterceptHandler interceptHandler) {
        if (!initialized) {
            throw new IllegalStateException("Can't deregister interceptors from a integration that is not yet started");
        }
        interceptor.removeInterceptHandler(interceptHandler);
    }
    
    /**
     * Return a list of descriptors of connected clients.
     * */
    public Collection<ClientDescriptor> listConnectedClients() {
        return sessions.listConnectedClients();
    }
}
