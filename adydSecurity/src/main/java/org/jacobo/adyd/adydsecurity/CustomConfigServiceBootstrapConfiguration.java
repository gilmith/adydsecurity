package org.jacobo.adyd.adydsecurity;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.config.client.ConfigClientProperties;
import org.springframework.cloud.config.client.ConfigServicePropertySourceLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CustomConfigServiceBootstrapConfiguration {

	@Value("${trust.store:keystore/springboot.p12}")
	private ClassPathResource trustStore;

	@Value("${trust.store.password:password}")
	private String trustStorePassword;

	@Autowired
	ConfigClientProperties configClientProperties;
	
	@Bean("trustedRestTemplate")
	public RestTemplate createTemplate() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException,
			CertificateException, IOException {
		SSLContext sslContext = new SSLContextBuilder()
				.loadTrustMaterial(trustStore.getURL(), trustStorePassword.toCharArray()).build();
		SSLConnectionSocketFactory sslConFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
		HttpClientConnectionManager cm = PoolingHttpClientConnectionManagerBuilder.create()
				.setSSLSocketFactory(sslConFactory).build();
		CloseableHttpClient httpClient = HttpClients.custom().setConnectionManager(cm).build();
		ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		return new RestTemplate(requestFactory);
	}

	@Bean
	public ConfigServicePropertySourceLocator configServicePropertySourceLocator() throws KeyManagementException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
		ConfigServicePropertySourceLocator configServicePropertySourceLocator = new ConfigServicePropertySourceLocator(
				configClientProperties);
		configServicePropertySourceLocator.setRestTemplate(createTemplate());
		return configServicePropertySourceLocator;
	}

}
