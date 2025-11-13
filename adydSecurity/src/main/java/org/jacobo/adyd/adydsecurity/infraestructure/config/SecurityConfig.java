package org.jacobo.adyd.adydsecurity.infraestructure.config;

import lombok.RequiredArgsConstructor;
import org.jacobo.adyd.adydsecurity.domain.entity.SecurityRule;
import org.jacobo.adyd.adydsecurity.domain.service.AuthServicePort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;


@Configuration
@RequiredArgsConstructor
public class SecurityConfig {


    private final AuthServicePort authServicePort;
    private final List<SecurityRule> securityRoutes;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 1. Deshabilitar la validación JWT automática de Spring
        //    (ya que la estamos haciendo manualmente en el filtro)
        http.oauth2ResourceServer(AbstractHttpConfigurer::disable);

        // 2. Deshabilitar CSRF (típico en APIs stateless)
        http.csrf(AbstractHttpConfigurer::disable);

        // 3. Añadir tu Filtro de la Librería *antes* de la lógica de autorización
        http.addFilterBefore(
                new KeycloakTokenFilter(authServicePort),
                UsernamePasswordAuthenticationFilter.class // Añadido en un punto temprano
        );

        // 4. Configurar la autorización (ahora usa el SecurityContext establecido por tu filtro)
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
        );

        return http.build();

//        http.sessionManagement(new Customizer<SessionManagementConfigurer<HttpSecurity>>() {
//            @Override
//            public void customize(SessionManagementConfigurer<HttpSecurity> session) {
//                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//            }
//        });
//        http.cors(cors -> cors.configurationSource(request -> {
//            CorsConfiguration configuration = new CorsConfiguration();
//            configuration.setAllowedOrigins(Arrays.asList("*"));
//            configuration.setAllowedMethods(Arrays.asList("*"));
//            configuration.setAllowedHeaders(Arrays.asList("*"));
//            return configuration;
//        }));
//        http.csrf(AbstractHttpConfigurer::disable);
//        http.authorizeHttpRequests(
//                (authorizeHttpRequests) -> {
//                    securityRoutes.forEach(rule -> {
//                        if (rule.authenticated()) {
//                            authorizeHttpRequests.requestMatchers(rule.method(), rule.path()).authenticated();
//                        } else {
//                            authorizeHttpRequests.requestMatchers(rule.method(), rule.path()).permitAll();
//                        }
//                    });
//                    authorizeHttpRequests.anyRequest().authenticated();
//                }
//        );
//        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
//        return http.build();

    }

}
