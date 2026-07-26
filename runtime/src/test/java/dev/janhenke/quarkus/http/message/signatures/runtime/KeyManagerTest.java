package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.nimbusds.jose.jwk.JWK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.janhenke.quarkus.http.message.signatures.runtime.HttpMessageSignaturesConfig.KeyConfig;
import io.quarkus.credentials.CredentialsProvider;
import jakarta.enterprise.inject.Instance;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyManagerTest
{
	private Instance<CredentialsProvider> credentialsProvider;
	private HttpMessageSignaturesConfig config;
	private KeyManager keyManager;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp()
	{
		credentialsProvider = mock(Instance.class);
		config = mock(HttpMessageSignaturesConfig.class);
		keyManager = new KeyManager(credentialsProvider, config);
	}

	@Test
	void testLoadJwkFromClasspath()
	{
		final KeyConfig keyConfig = mock(KeyConfig.class);
		when(keyConfig.location()).thenReturn(Optional.of("classpath:test.jwk"));
		when(keyConfig.type()).thenReturn(KeyConfig.Type.JWK);
		when(config.keys()).thenReturn(Map.of("test-rsa", keyConfig));

		keyManager.init();

		final Optional<JWK> jwk = keyManager.getPublicKey("test-rsa");
		assertThat(jwk).isPresent();
		assertThat(jwk.get().getKeyID()).isEqualTo("test-rsa");
	}

	@Test
	void testLoadJwksFromClasspath()
	{
		final KeyConfig keyConfig = mock(KeyConfig.class);
		when(keyConfig.location()).thenReturn(Optional.of("classpath:test.jwks"));
		when(keyConfig.type()).thenReturn(KeyConfig.Type.JWKS);
		when(config.keys()).thenReturn(Map.of("test-rsa-1", keyConfig));

		keyManager.init();

		final Optional<JWK> jwk = keyManager.getPublicKey("test-rsa-1");
		assertThat(jwk).isPresent();
		assertThat(jwk.get().getKeyID()).isEqualTo("test-rsa-1");
	}

	@Test
	void testLoadPemFromClasspath()
	{
		final KeyConfig keyConfig = mock(KeyConfig.class);
		when(keyConfig.location()).thenReturn(Optional.of("classpath:test.pem"));
		when(keyConfig.type()).thenReturn(KeyConfig.Type.PEM);
		when(config.keys()).thenReturn(Map.of("test-pem", keyConfig));

		keyManager.init();

		final Optional<JWK> jwk = keyManager.getPublicKey("test-pem");
		assertThat(jwk).isPresent();
		assertThat(jwk.get().getKeyID()).isEqualTo("test-pem");
	}

	@Test
	void testLoadMissingKey()
	{
		when(config.keys()).thenReturn(Collections.emptyMap());
		keyManager.init();
		assertThat(keyManager.getPublicKey("any")).isEmpty();
	}

	@Test
	void testLoadKeyWithMissingLocation()
	{
		final KeyConfig keyConfig = mock(KeyConfig.class);
		when(keyConfig.location()).thenReturn(Optional.empty());
		when(config.keys()).thenReturn(Map.of("test-key", keyConfig));

		assertThatThrownBy(() -> keyManager.init())
				.isInstanceOf(RuntimeException.class)
				.hasMessageContaining("Failed to load key")
				.hasCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void testLoadKeyWithInvalidClasspathLocation()
	{
		final KeyConfig keyConfig = mock(KeyConfig.class);
		when(keyConfig.location()).thenReturn(Optional.of("classpath:non-existent.jwk"));
		when(keyConfig.type()).thenReturn(KeyConfig.Type.JWK);
		when(config.keys()).thenReturn(Map.of("test-key", keyConfig));

		assertThatThrownBy(() -> keyManager.init())
				.isInstanceOf(RuntimeException.class)
				.hasMessageContaining("Failed to load key");
	}
}
