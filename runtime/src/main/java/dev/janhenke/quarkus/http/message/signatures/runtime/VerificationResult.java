package dev.janhenke.quarkus.http.message.signatures.runtime;

/**
 * Result of a verification attempt.
 *
 * @author Jan Henke
 */
public record VerificationResult(boolean valid, String principalName, String failureReason)
{
	/**
	 * Creates a successful verification result.
	 *
	 * @param principalName the name of the principal that was verified.
	 *
	 */
	static VerificationResult success(final String principalName)
	{
		return new VerificationResult(true, principalName, null);
	}

	/**
	 * Creates a failed verification result.
	 *
	 * @param failureReason the reason for the failure.
	 *
	 */
	static VerificationResult failure(final String failureReason)
	{
		return new VerificationResult(false, null, failureReason);
	}

	/**
	 * Determines if the verification result represents an empty state.
	 *
	 * @return {@code true} if the verification result is valid and the principal name is null,
	 * otherwise {@code false}.
	 */
	public boolean isEmpty()
	{
		return valid() && principalName() == null;
	}
}
