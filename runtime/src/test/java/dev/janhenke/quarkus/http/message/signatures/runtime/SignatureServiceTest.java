package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.jwk.JWK;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import dev.janhenke.quarkus.http.message.signatures.runtime.HttpMessageSignaturesConfig.VerifyConfig;
import jakarta.enterprise.inject.Instance;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

class SignatureServiceTest
{
	private Clock clock;
	private KeyManager keyManager;
	private HttpMessageSignaturesConfig config;
	private Instance<VertxSignatureContext> requestContextInstance;
	private VertxSignatureContext requestContext;
	private SignatureService signatureService;
	private VerifyConfig verifyConfig;

	@BeforeEach
	@SuppressWarnings("unchecked")
	void setUp()
	{
		clock = Clock.fixed(Instant.parse("2021-04-20T10:00:00Z"), ZoneId.of("UTC"));
		keyManager = mock(KeyManager.class);
		config = mock(HttpMessageSignaturesConfig.class);
		requestContextInstance = mock(Instance.class);
		requestContext = mock(VertxSignatureContext.class);

		final Instance<Clock> clockInstance = mock(Instance.class);
		when(clockInstance.isResolvable()).thenReturn(true);
		when(clockInstance.get()).thenReturn(clock);

		when(requestContextInstance.isResolvable()).thenReturn(true);
		when(requestContextInstance.get()).thenReturn(requestContext);

		signatureService = new SignatureService(clockInstance, keyManager, config, requestContextInstance);

		verifyConfig = mock(VerifyConfig.class);
		when(config.verify()).thenReturn(verifyConfig);
		when(verifyConfig.allowedAlgorithms()).thenReturn(List.of("rsa-v1_5-sha256", "RS256"));
		when(verifyConfig.maxSkew()).thenReturn(Duration.ofMinutes(5));
		when(verifyConfig.requiredComponents()).thenReturn(Collections.emptyList());
	}

	@Test
	void testNoRequestContext()
	{
		when(requestContextInstance.isResolvable()).thenReturn(false);
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("No active HTTP request context");
	}

	@Test
	void testParsingFailure()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("invalid");
		when(requestContext.getSignatureHeader()).thenReturn("invalid");
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Parsing signature failed");
	}

	@Test
	void testNoSignatureAlgorithm()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;keyid=\"test-key\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("No signature algorithm found");
	}

	@Test
	void testAlgorithmNotAllowed()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;keyid=\"test-key\";alg=\"forbidden\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Signature algorithm not allowed");
	}

	@Test
	void testNoKeyId()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("No keyid found");
	}

	@Test
	void testNoPublicKeyFound()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.empty());
		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("No public key found");
	}

	@Test
	void testMissingRequiredComponent()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(verifyConfig.requiredComponents()).thenReturn(List.of("@path"));
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(mock(JWK.class)));

		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Missing required component: @path");
	}

	@Test
	void testMissingCreationTimestamp()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(mock(JWK.class)));

		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Missing creation timestamp");
	}

	@Test
	void testSignatureCreatedInFuture()
	{
		// now = 2021-04-20T10:00:00Z (1618912800)
		// created = now + 10 minutes = 1618913400
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618913400;keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(mock(JWK.class)));

		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Signature created in the future");
	}

	@Test
	void testMissingExpirationTimestamp()
	{
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912800;keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(mock(JWK.class)));

		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Missing expiration timestamp");
	}

	@Test
	void testSignatureExpired()
	{
		// now = 2021-04-20T10:00:00Z (1618912800)
		// expires = now - 10 minutes = 1618912200
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\");created=1618912000;expires=1618912200;keyid=\"test-key\";alg=\"rsa-v1_5-sha256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(mock(JWK.class)));

		final VerificationResult result = signatureService.verify();
		assertThat(result.valid()).isFalse();
		assertThat(result.failureReason()).contains("Signature has expired");
	}

	@Test
	void testSuccess() throws Exception
	{
		// 1. Prepare key
		JWK jwk = mock(JWK.class);
		when(keyManager.getPublicKey("test-key")).thenReturn(Optional.of(jwk));

		// 2. Prepare context
		when(requestContext.getSignatureInputHeader()).thenReturn("sig1=(\"@method\" \"@path\");created=1618912800;expires=1618916400;keyid=\"test-key\";alg=\"RS256\"");
		when(requestContext.getSignatureHeader()).thenReturn("sig1=:abc:");
		when(requestContext.getComponentValue(any(), any())).thenAnswer(invocation -> {
			ComponentIdentifier id = invocation.getArgument(1);
			if (id.getComponentName().equals("@method"))
			{
				return "GET";
			}
			if (id.getComponentName().equals("@path"))
			{
				return "/test";
			}
			return null;
		});

		// 3. Mock JoseHttpVerifier
		try (var mockedVerifier = mockConstruction(JoseHttpVerifier.class, (mock, context) -> {
			when(mock.verify(any(), any())).thenReturn(true);
		}))
		{
			// 4. Verify
			final VerificationResult result = signatureService.verify();
			assertThat(result.valid()).isTrue();
			assertThat(result.principalName()).isEqualTo("test-key");
		}
	}
}
