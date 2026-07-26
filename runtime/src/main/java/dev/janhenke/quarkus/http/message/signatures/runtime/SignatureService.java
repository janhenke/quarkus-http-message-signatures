package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.SignatureBase;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureField;
import com.authlete.hms.SignatureInputField;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.impl.JoseHttpVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;

import jakarta.annotation.Nonnull;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.security.SignatureException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Service for signing and verifying HTTP messages.
 *
 * @author Jan Henke
 */
@ApplicationScoped
public class SignatureService
{
	private final Clock clock;
	private final KeyManager keyManager;
	private final HttpMessageSignaturesConfig config;
	private final Instance<VertxSignatureContext> requestContext;

	@Inject
	public SignatureService(@Nonnull final Instance<Clock> clockInstance,
	                        final KeyManager keyManager,
	                        final HttpMessageSignaturesConfig config,
	                        final Instance<VertxSignatureContext> requestContext)
	{
		this.clock = clockInstance.isResolvable() ? clockInstance.get() : Clock.systemUTC();
		this.keyManager = keyManager;
		this.config = config;
		this.requestContext = requestContext;
	}

	public VerificationResult verify()
	{
		if (!requestContext.isResolvable())
		{
			return VerificationResult.failure("No active HTTP request context");
		}

		final VertxSignatureContext ctx = requestContext.get();

		final SignatureInputField signatureInputField;
		final SignatureField signatureField;
		try
		{
			signatureInputField = SignatureInputField.parse(ctx.getSignatureInputHeader());
			signatureField = SignatureField.parse(ctx.getSignatureHeader());
		}
		catch (final SignatureException e)
		{
			return VerificationResult.failure("Parsing signature failed: " + e.getMessage());
		}

		String principalName = null;
		for (final var entry : signatureInputField.entrySet())
		{
			final String label = entry.getKey();
			final SignatureMetadata signatureInput = entry.getValue();
			final SignatureMetadataParameters parameters = signatureInput.getParameters();
			final String keyid = parameters.getKeyid();
			final String signatureAlgorithm = parameters.getAlg();

			// validate algorithm
			if (signatureAlgorithm == null)
			{
				return VerificationResult.failure("No signature algorithm found for keyid: " + keyid);
			}
			if (!config.verify().allowedAlgorithms().contains(signatureAlgorithm))
			{
				return VerificationResult.failure("Signature algorithm not allowed for keyid: " + keyid);
			}

			// load key
			if (keyid == null)
			{
				return VerificationResult.failure("No keyid found for signature input");
			}
			final Optional<JWK> key = keyManager.getPublicKey(keyid);
			if (key.isEmpty())
			{
				return VerificationResult.failure("No public key found for keyid: " + keyid);

			}

			// validate all required components are included in the signature
			final SignatureMetadata metadata = new SignatureMetadata(signatureInput);
			for (final String componentName : config.verify().requiredComponents())
			{
				final boolean componentMissing = metadata.stream()
				                                         .map(ComponentIdentifier::getComponentName)
				                                         .noneMatch(componentName::equals);
				if (componentMissing)
				{
					return VerificationResult.failure("Missing required component: " + componentName);
				}
			}

			// validate creation and expiration timestamps
			final var now = Instant.now(clock);
			final Duration maxSkew = config.verify().maxSkew();
			final Instant creationTimestamp = parameters.getCreated();
			if (creationTimestamp == null)
			{
				return VerificationResult.failure("Missing creation timestamp");
			}
			if (creationTimestamp.isAfter(now.plus(maxSkew)))
			{
				return VerificationResult.failure("Signature created in the future");
			}
			final Instant expirationTimestamp = parameters.getExpires();
			if (expirationTimestamp == null)
			{
				return VerificationResult.failure("Missing expiration timestamp");
			}
			if (now.isAfter(expirationTimestamp.plus(maxSkew)))
			{
				return VerificationResult.failure("Signature has expired");
			}

			// crypto validation of the actual signature
			final SignatureBase base;
			try
			{
				base = new SignatureBaseBuilder(ctx).build(metadata);
				final var verifier = new JoseHttpVerifier(key.get(), JWSAlgorithm.parse(signatureAlgorithm));
				if (!base.verify(verifier, signatureField.get(label)))
				{
					return VerificationResult.failure("Invalid signature for keyid: " + keyid);
				}
			}
			catch (final SignatureException e)
			{
				return VerificationResult.failure("Signature verification failed: " + e.getMessage());
			}
			if (principalName == null)
			{
				principalName = keyid;
			}
		}

		return VerificationResult.success(principalName);
	}
}
