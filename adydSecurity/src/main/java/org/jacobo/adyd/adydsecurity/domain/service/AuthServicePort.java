package org.jacobo.adyd.adydsecurity.domain.service;

import org.jacobo.adyd.adydsecurity.domain.entity.UserIdentity;

public interface AuthServicePort {
    UserIdentity validateToken(String rawToken);
}