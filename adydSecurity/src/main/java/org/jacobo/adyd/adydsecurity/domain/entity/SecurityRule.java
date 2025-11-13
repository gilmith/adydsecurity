package org.jacobo.adyd.adydsecurity.domain.entity;

public record SecurityRule(String method, String path, Boolean authenticated) {
}
