package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import dev.janhenke.quarkus.http.message.signatures.runtime.HttpMessageSignaturesConfig.KeyConfig;
import io.quarkus.credentials.CredentialsProvider;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages the keys used for signature creation and verification.
 *
 * @author Jan Henke
 */
@ApplicationScoped
public class KeyManager
{
	private final Instance<CredentialsProvider> credentialsProvider;
	private final HttpMessageSignaturesConfig config;

	private final Map<String, JWK> keys = new ConcurrentHashMap<>();

	@Inject
	public KeyManager(final Instance<CredentialsProvider> credentialsProvider, final HttpMessageSignaturesConfig config)
	{
		this.credentialsProvider = credentialsProvider;
		this.config = config;
	}

	@PostConstruct
	public void init()
	{
		config.keys().forEach((kid, keyConfig) -> {
			try
			{
				keys.put(kid, loadKey(kid, keyConfig));
			}
			catch (final Exception e)
			{
				// Throwing an exception here will prevent the application from starting with an invalid security config
				throw new RuntimeException("Failed to load key with id: " + kid, e);
			}
		});
	}

	private @Nonnull JWK loadKey(String kid, @Nonnull KeyConfig keyConfig) throws Exception
	{
		final String location = keyConfig.location()
		                                 .orElseThrow(() -> new IllegalArgumentException(
				                                 "Location is required for key: " + kid));

		return switch (keyConfig.type())
		{
			case JWK ->
			{
				// Load a single JWK from the specified location
				String content = loadContent(location);
				yield JWK.parse(content);
			}
			case JWKS ->
			{
				// Load a Key Set and find the key matching the configuration ID
				String content = loadContent(location);
				yield JWKSet.parse(content).getKeyByKeyId(kid);
			}
			case PEM ->
			{
				final String content = loadContent(location);
				final JWK parsedJwk = JWK.parseFromPEMEncodedObjects(content);

				// Inject the kid from config into the JWK object
				final Map<String, Object> json = parsedJwk.toJSONObject();
				json.put("kid", kid);

				yield JWK.parse(json);
			}
			case KEYSTORE ->
			{
				final char[] password = resolvePassword(keyConfig);
				final KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

				// Priority: 1. keyStoreFile (Path), 2. location (String/URL)
				if (keyConfig.keyStoreFile().isPresent())
				{
					try (var is = Files.newInputStream(keyConfig.keyStoreFile().get()))
					{
						ks.load(is, password);
					}
				}
				else
				{
					try (var is = openInputStream(location))
					{
						ks.load(is, password);
					}
				}

				// Extract the key using the kid as the alias.
				if (ks.containsAlias(kid))
				{
					final Key key = ks.getKey(kid, password);
					final Certificate certificate = ks.getCertificate(kid);
					final PublicKey publicKey = (certificate != null) ? certificate.getPublicKey() : null;

					if (key instanceof RSAPrivateKey || publicKey instanceof RSAPublicKey)
					{
						yield RSAKey.load(ks, kid, password);
					}
					else if (key instanceof ECPrivateKey || publicKey instanceof ECPublicKey)
					{
						yield ECKey.load(ks, kid, password);
					}
				}
				throw new IllegalArgumentException("Alias '" + kid + "' not found or unsupported key type in keystore");
			}
		};
	}

	private @Nonnull String loadContent(final @Nonnull String location)
	{
		try (InputStream is = openInputStream(location))
		{
			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		}
		catch (final IOException e)
		{
			throw new IllegalArgumentException("Failed to load content from location: " + location, e);
		}
	}

	@Nonnull
	private InputStream openInputStream(@Nonnull String location) throws IOException
	{
		if (location.startsWith("classpath:"))
		{
			var is = Thread.currentThread().getContextClassLoader().getResourceAsStream(location.substring(10));

			if (is == null)
			{
				throw new FileNotFoundException(location);
			}
			return is;
		}
		else if (location.startsWith("http"))
		{
			try (var client = HttpClient.newHttpClient())
			{
				var request = HttpRequest.newBuilder()
				                         .uri(new URI(location))
				                         .timeout(Duration.ofSeconds(10))
				                         .GET()
				                         .build();

				var response = client.send(request, BodyHandlers.ofByteArray());

				if (response.statusCode() != 200)
				{
					throw new IOException("Failed to load key from "
							                      + location
							                      + ", status code: "
							                      + response.statusCode());
				}

				return new ByteArrayInputStream(response.body());
			}
			catch (final URISyntaxException e)
			{
				throw new RuntimeException("Invalid HTTP URL " + location, e);
			}
			catch (final InterruptedException e)
			{
				Thread.currentThread().interrupt();
				throw new IOException("Interrupted while loading key from " + location, e);
			}
		}
		else
		{
			// Assume it's a local file path
			return Files.newInputStream(Path.of(location));
		}
	}

	@Nullable
	private char[] resolvePassword(@Nonnull KeyConfig keyConfig)
	{
		String password = keyConfig.password().orElse(null);

		// If a secret provider is configured, it takes precedence
		if (keyConfig.secretProvider().isPresent() && credentialsProvider.isResolvable())
		{
			var credentials = credentialsProvider.get().getCredentials(keyConfig.secretProvider().get());
			if (credentials != null && credentials.containsKey("password"))
			{
				password = credentials.get("password");
			}
		}

		return password != null ? password.toCharArray() : null;
	}

	public Optional<JWK> getPublicKey(final String keyId)
	{
		return Optional.ofNullable(keys.get(keyId));
	}
}
