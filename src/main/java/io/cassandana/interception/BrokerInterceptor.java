/*
 *  Copyright 2019 Mohammad Taqi Soleimani
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package io.cassandana.interception;

import io.cassandana.broker.config.Config;
import io.cassandana.broker.subscriptions.Subscription;
import io.cassandana.interception.messages.*;
import io.netty.handler.codec.mqtt.MqttConnectMessage;
import io.netty.handler.codec.mqtt.MqttPublishMessage;
import io.netty.util.ReferenceCountUtil;

import static io.cassandana.logging.LoggingUtils.getInterceptorIds;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * An interceptor that execute the interception tasks asynchronously.
 */
public final class BrokerInterceptor implements Interceptor {

    private final Map<Class<?>, List<InterceptHandler>> handlers;
    private final ExecutorService executor;

    private BrokerInterceptor(int poolSize, List<InterceptHandler> handlers) {
        this.handlers = new HashMap<>();
        for (Class<?> messageType : InterceptHandler.ALL_MESSAGE_TYPES) {
            this.handlers.put(messageType, new CopyOnWriteArrayList<InterceptHandler>());
        }
        for (InterceptHandler handler : handlers) {
            this.addInterceptHandler(handler);
        }
        executor = Executors.newFixedThreadPool(poolSize);
    }

    /**
     * Configures a broker interceptor, with a thread pool of one thread.
     *
     * @param handlers InterceptHandlers listeners.
     */
    public BrokerInterceptor(List<InterceptHandler> handlers) {
        this(1, handlers);
    }

    /**
     * Configures a broker interceptor using the pool size specified in the IConfig argument.
     * @param props configuration properties.
     * @param handlers InterceptHandlers listeners.
     *
     */
    public BrokerInterceptor(Config conf, List<InterceptHandler> handlers) {
        this(conf.threads, handlers);
    }

    /**
     * Shutdown graciously the executor service
     */
    void stop() {
        executor.shutdown();
        try {
            executor.awaitTermination(10L, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        }
        if (!executor.isTerminated()) {
            executor.shutdownNow();
        }
    }

    @Override
    public void notifyClientConnected(final MqttConnectMessage msg) {
        for (final InterceptHandler handler : this.handlers.get(InterceptConnectMessage.class)) {
            executor.execute(() -> handler.onConnect(new InterceptConnectMessage(msg)));
        }
    }

    @Override
    public void notifyClientDisconnected(final String clientID, final String username) {
        for (final InterceptHandler handler : this.handlers.get(InterceptDisconnectMessage.class)) {
            executor.execute(() -> handler.onDisconnect(new InterceptDisconnectMessage(clientID, username)));
        }
    }

    @Override
    public void notifyClientConnectionLost(final String clientID, final String username) {
        for (final InterceptHandler handler : this.handlers.get(InterceptConnectionLostMessage.class)) {
            executor.execute(() -> handler.onConnectionLost(new InterceptConnectionLostMessage(clientID, username)));
        }
    }

    @Override
    public void notifyTopicPublished(final MqttPublishMessage msg, final String clientID, final String username) {
        msg.retain();

        executor.execute(() -> {
                try {
                    for (InterceptHandler handler : handlers.get(InterceptPublishMessage.class)) {

                        handler.onPublish(new InterceptPublishMessage(msg, clientID, username));
                    }
                } finally {
                    ReferenceCountUtil.release(msg);
                }
        });
    }

    @Override
    public void notifyTopicSubscribed(final Subscription sub, final String username) {
        for (final InterceptHandler handler : this.handlers.get(InterceptSubscribeMessage.class)) {
            executor.execute(() -> handler.onSubscribe(new InterceptSubscribeMessage(sub, username)));
        }
    }

    @Override
    public void notifyTopicUnsubscribed(final String topic, final String clientID, final String username) {
        for (final InterceptHandler handler : this.handlers.get(InterceptUnsubscribeMessage.class)) {
            executor.execute(() -> handler.onUnsubscribe(new InterceptUnsubscribeMessage(topic, clientID, username)));
        }
    }

    @Override
    public void notifyMessageAcknowledged(final InterceptAcknowledgedMessage msg) {
        for (final InterceptHandler handler : this.handlers.get(InterceptAcknowledgedMessage.class)) {
            executor.execute(() -> handler.onMessageAcknowledged(msg));
        }
    }

    @Override
    public void addInterceptHandler(InterceptHandler interceptHandler) {
        Class<?>[] interceptedMessageTypes = getInterceptedMessageTypes(interceptHandler);
        for (Class<?> interceptMessageType : interceptedMessageTypes) {
            this.handlers.get(interceptMessageType).add(interceptHandler);
        }
    }

    @Override
    public void removeInterceptHandler(InterceptHandler interceptHandler) {
        Class<?>[] interceptedMessageTypes = getInterceptedMessageTypes(interceptHandler);
        for (Class<?> interceptMessageType : interceptedMessageTypes) {
            this.handlers.get(interceptMessageType).remove(interceptHandler);
        }
    }

    private static Class<?>[] getInterceptedMessageTypes(InterceptHandler interceptHandler) {
        Class<?>[] interceptedMessageTypes = interceptHandler.getInterceptedMessageTypes();
        if (interceptedMessageTypes == null) {
            return InterceptHandler.ALL_MESSAGE_TYPES;
        }
        return interceptedMessageTypes;
    }
}
