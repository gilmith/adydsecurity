package org.jacobo.adyd.adydsecurity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class FileRouteConfiguration {

    private final ResourceLoader resourceLoader;
    private ObjectMapper objectMapper;


    @Bean
    public List<SecurityRule> securityRoutesFromFile() {
        this.objectMapper = new ObjectMapper();
        try (InputStream inputStream = resourceLoader.getResource("classpath:security-routes.json").getInputStream()) {
            return objectMapper.readValue(inputStream, new TypeReference<List<SecurityRule>>() {});
        } catch (IOException e) {
            throw new RuntimeException("Error al leer el archivo de rutas de seguridad", e);
        }
    }
}
