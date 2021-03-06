/*
 *  Copyright 2019 Mohammad Taqi Soleimani
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package io.cassandana.broker.security;

import io.cassandana.broker.subscriptions.Topic;

public class DenyAllAuthorizatorPolicy implements IAuthorizatorPolicy {

    @Override
    public boolean canWrite(Topic topic, String user, String client) {
        return false;
    }

    @Override
    public boolean canRead(Topic topic, String user, String client) {
        return false;
    }
}
