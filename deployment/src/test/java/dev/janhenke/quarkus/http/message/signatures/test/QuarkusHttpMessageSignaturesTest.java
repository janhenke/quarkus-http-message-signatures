package dev.janhenke.quarkus.http.message.signatures.test;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class QuarkusHttpMessageSignaturesTest
{

	// Start unit test with your extension loaded
	@RegisterExtension
	static final QuarkusUnitTest unitTest = new QuarkusUnitTest().setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class))
	                                                             .overrideConfigKey(
			                                                             "quarkus.http.signatures.verify.allowed-algorithms",
			                                                             "foobar")
	                                                             .overrideConfigKey(
			                                                             "quarkus.http.signatures.verify.required-components",
			                                                             "foobar");

	@Test
	public void writeYourOwnUnitTest()
	{
		// Write your unit tests here - see the testing extension guide https://quarkus.io/guides/writing-extensions#testing-extensions for more information
		Assertions.assertTrue(true, "Add some assertions to " + getClass().getName());
	}
}
