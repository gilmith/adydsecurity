package org.jacobo.adyd.adydsecurity.infraestructure.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jacobo.adyd.adydsecurity.domain.entity.UserIdentity;
import org.jacobo.adyd.adydsecurity.domain.service.AuthServicePort;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class KeycloakTokenFilter extends OncePerRequestFilter {

    private final AuthServicePort authServicePort; // ¡El puerto de tu Dominio!

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Extraer el token de la cabecera
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String rawToken = authHeader.substring(7);

        try {
            // 2. Usar el PUERTO de Dominio para validar
            UserIdentity userIdentity = authServicePort.validateToken(rawToken);

            // 3. Crear el objeto de autenticación de Spring Security
            // Mapea tu objeto UserIdentity (Dominio) a un objeto de Spring
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userIdentity.getUserId(), // Principal: ID del usuario
                            null, // Credenciales: null, ya que el token se ha consumido
                            userIdentity.getAuthorities() // Authorities: Roles o Permisos
                    );

            // 4. Establecer la identidad en el contexto de seguridad de Spring
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (Exception e) {
            // Manejo de errores: token expirado, firma inválida, etc.
            // Aquí podrías enviar una respuesta 401 Unauthorized directamente.
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
