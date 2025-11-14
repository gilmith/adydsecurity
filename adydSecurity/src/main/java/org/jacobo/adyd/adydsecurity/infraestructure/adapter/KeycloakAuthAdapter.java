package org.jacobo.adyd.adydsecurity.infraestructure.adapter;

import lombok.RequiredArgsConstructor;
import org.jacobo.adyd.adydsecurity.domain.entity.UserIdentity;
import org.jacobo.adyd.adydsecurity.domain.service.AuthServicePort;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class KeycloakAuthAdapter implements AuthServicePort {

    private final JwtDecoder jwtDecoder; // Inyectado por Spring Security

    @Override
    public UserIdentity validateToken(String rawToken) {
// 1. Lógica de validación del token de Keycloak (usa jwtDecoder)
        Jwt jwt = jwtDecoder.decode(rawToken); // Spring verifica firma, expiración, etc.

        // 2. Mapeo de Claims del JWT a la Entidad de Dominio
        String userId = jwt.getClaimAsString("sub");
        List<String> roles = extractRoles(jwt); // Lógica para extraer roles del claim "realm_access" o "resource_access"

        // 3. Devolver el objeto de Dominio
        return new UserIdentity(userId, roles);
    }

    private List<String> extractRoles(Jwt jwt) {
        return List.of();
    }
}
