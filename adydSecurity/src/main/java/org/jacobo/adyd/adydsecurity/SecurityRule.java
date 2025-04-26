package org.jacobo.adyd.adydsecurity;

public record SecurityRule(String method, String path, Boolean authenticated) {
}
