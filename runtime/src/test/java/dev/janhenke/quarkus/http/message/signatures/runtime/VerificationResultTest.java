package dev.janhenke.quarkus.http.message.signatures.runtime;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationResultTest
{
	@Test
	void testSuccess()
	{
		final VerificationResult result = VerificationResult.success("test-principal");
		assertThat(result.valid()).isTrue();
		assertThat(result.principalName()).isEqualTo("test-principal");
		assertThat(result.failureReason()).isNull();
		assertThat(result.isEmpty()).isFalse();
	}

	@Test
	void testFailure()
	{
		final VerificationResult result = VerificationResult.failure("test-failure");
		assertThat(result.valid()).isFalse();
		assertThat(result.principalName()).isNull();
		assertThat(result.failureReason()).isEqualTo("test-failure");
		assertThat(result.isEmpty()).isFalse();
	}

	@Test
	void testIsEmpty()
	{
		final VerificationResult result = new VerificationResult(true, null, null);
		assertThat(result.isEmpty()).isTrue();
	}

	@Test
	void testIsNotEmptyWhenInvalid()
	{
		final VerificationResult result = new VerificationResult(false, null, null);
		assertThat(result.isEmpty()).isFalse();
	}

	@Test
	void testIsNotEmptyWhenHasPrincipal()
	{
		final VerificationResult result = new VerificationResult(true, "some-principal", null);
		assertThat(result.isEmpty()).isFalse();
	}
}
