package dev.janhenke.quarkus.http.message.signatures.runtime;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/// Configuration for the HTTP message signatures extension.
///
/// @author Jan Henke
@ConfigMapping(prefix = "quarkus.http.signatures")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface HttpMessageSignaturesConfig
{
	/// `true` if the extension is enabled, `false` otherwise.
	@WithDefault("true")
	boolean enabled();

	/// Configuration for the signature verification.
	VerifyConfig verify();

	/// Configuration for the signature creation.
	SignConfig sign();

	/// The list of keys used for signature creation and verification.
	Map<String, KeyConfig> keys();

	/// Configuration for the signature verification.
	@ConfigGroup
	interface VerifyConfig
	{
		/// `true` if the signature verification is enabled, `false` otherwise.
		@WithDefault("true")
		boolean enabled();

		/// The policy for the signature verification.
		@WithDefault("ENFORCED")
		Policy policy();

		/// The list of required components.
		List<String> requiredComponents();

		/// The list of allowed algorithms.
		List<String> allowedAlgorithms();

		/// The maximum skew allowed for the signature.
		@WithDefault("PT5M")
		Duration maxSkew();

		/// The policy for the signature verification.
		enum Policy
		{
			/// The signature verification is enforced.
			ENFORCED,
			/// The signature verification is permissive.
			PERMISSIVE
		}
	}

	/// Configuration for the signature creation.
	@ConfigGroup
	interface SignConfig
	{
		/// `true` if the signature creation is enabled, `false` otherwise.
		@WithDefault("true")
		boolean enabled();
	}

	/// Configuration for the keys used for signature creation and verification.
	@ConfigGroup
	interface KeyConfig
	{
		/// The location of the key. Either a file path or a URL.
		Optional<String> location();

		/// The type of the key.
		Type type();

		/// An optional path to the key store file.
		Optional<Path> keyStoreFile();

		/// The password for the encrypted keys or key store file.
		Optional<String> password();

		/// An optional secret provider to use for the key.
		Optional<String> secretProvider();

		enum Type
		{
			/// Privacy Enhanced Mail format
			PEM,
			/// JSON Web Key
			JWK,
			/// JSON Web Key Set
			JWKS,
			/// Java Keystore
			KEYSTORE
		}
	}
}
