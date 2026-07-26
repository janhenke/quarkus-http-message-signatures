package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentIdentifierParameters;
import com.authlete.hms.SignatureInputField;
import com.authlete.hms.SignatureMetadata;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.HostAndPort;
import io.vertx.ext.web.RoutingContext;
import java.security.SignatureException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VertxSignatureContextTest
{
	private RoutingContext routingContext;
	private HttpServerRequest request;
	private VertxSignatureContext context;

	@BeforeEach
	void setUp()
	{
		routingContext = mock(RoutingContext.class);
		request = mock(HttpServerRequest.class);
		when(routingContext.request()).thenReturn(request);
		context = new VertxSignatureContext(routingContext);
	}

	@Test
	void testGetDerivedComponentMethod() throws SignatureException
	{
		when(request.method()).thenReturn(HttpMethod.GET);
		final ComponentIdentifier identifier = new ComponentIdentifier("@method");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("GET");
	}

	@Test
	void testGetDerivedComponentTargetUri() throws SignatureException
	{
		when(request.absoluteURI()).thenReturn("https://example.com/path?query");
		final ComponentIdentifier identifier = new ComponentIdentifier("@target-uri");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("https://example.com/path?query");
	}

	@Test
	void testGetDerivedComponentAuthorityDefaultPort() throws SignatureException
	{
		when(request.authority()).thenReturn(HostAndPort.create("example.com", 443));
		when(request.scheme()).thenReturn("https");
		final ComponentIdentifier identifier = new ComponentIdentifier("@authority");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("example.com");
	}

	@Test
	void testGetDerivedComponentAuthorityNonDefaultPort() throws SignatureException
	{
		when(request.authority()).thenReturn(HostAndPort.create("example.com", 8443));
		when(request.scheme()).thenReturn("https");
		final ComponentIdentifier identifier = new ComponentIdentifier("@authority");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("example.com:8443");
	}

	@Test
	void testGetDerivedComponentScheme() throws SignatureException
	{
		when(request.scheme()).thenReturn("https");
		final ComponentIdentifier identifier = new ComponentIdentifier("@scheme");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("https");
	}

	@Test
	void testGetDerivedComponentRequestTarget() throws SignatureException
	{
		when(request.uri()).thenReturn("/path?query");
		final ComponentIdentifier identifier = new ComponentIdentifier("@request-target");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("/path?query");
	}

	@Test
	void testGetDerivedComponentPath() throws SignatureException
	{
		when(request.path()).thenReturn("/path");
		final ComponentIdentifier identifier = new ComponentIdentifier("@path");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("/path");
	}

	@Test
	void testGetDerivedComponentQuery() throws SignatureException
	{
		when(request.query()).thenReturn("param=value");
		final ComponentIdentifier identifier = new ComponentIdentifier("@query");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("?param=value");
	}

	@Test
	void testGetDerivedComponentQueryEmpty() throws SignatureException
	{
		when(request.query()).thenReturn("");
		final ComponentIdentifier identifier = new ComponentIdentifier("@query");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("");
	}

	@Test
	void testGetDerivedComponentQueryNull() throws SignatureException
	{
		when(request.query()).thenReturn(null);
		final ComponentIdentifier identifier = new ComponentIdentifier("@query");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("");
	}

	@Test
	void testGetDerivedComponentQueryParam() throws Exception
	{
		final MultiMap queryParams = MultiMap.caseInsensitiveMultiMap();
		queryParams.add("param", "value");
		when(routingContext.queryParams()).thenReturn(queryParams);
		final SignatureInputField sif = SignatureInputField.parse("sig=(\"@query-param\";name=\"param\")");
		final SignatureMetadata metadata = sif.get("sig");
		final ComponentIdentifier identifier = metadata.get(0);
		assertThat(context.getComponentValue(metadata, identifier)).isEqualTo("value");
	}

	@Test
	void testGetDerivedComponentQueryParamMissingName() throws Exception
	{
		final ComponentIdentifier identifier = mock(ComponentIdentifier.class);
		when(identifier.getComponentName()).thenReturn("@query-param");
		when(identifier.isDerivedComponent()).thenReturn(true);
		final ComponentIdentifierParameters parameters = mock(ComponentIdentifierParameters.class);
		when(identifier.getParameters()).thenReturn(parameters);
		when(parameters.getName()).thenReturn(null);

		assertThatThrownBy(() -> context.getComponentValue(null, identifier))
				.isInstanceOf(SignatureException.class)
				.hasMessageContaining("missing 'name' parameter");
	}

	@Test
	void testGetDerivedComponentQueryParamNotFound() throws Exception
	{
		when(routingContext.queryParams()).thenReturn(MultiMap.caseInsensitiveMultiMap());
		final SignatureInputField sif = SignatureInputField.parse("sig=(\"@query-param\";name=\"param\")");
		final SignatureMetadata metadata = sif.get("sig");
		final ComponentIdentifier identifier = metadata.get(0);
		assertThatThrownBy(() -> context.getComponentValue(metadata, identifier))
				.isInstanceOf(SignatureException.class)
				.hasMessageContaining("not found");
	}

	@Test
	void testGetDerivedComponentUnsupported()
	{
		final ComponentIdentifier identifier = new ComponentIdentifier("@unsupported");
		assertThatThrownBy(() -> context.getComponentValue(null, identifier))
				.isInstanceOf(SignatureException.class)
				.hasMessageContaining("Unsupported derived component");
	}

	@Test
	void testGetHeaderComponent() throws SignatureException
	{
		final MultiMap headers = MultiMap.caseInsensitiveMultiMap();
		headers.add("X-Test", "Value1");
		headers.add("X-Test", "Value2");
		when(request.headers()).thenReturn(headers);
		final ComponentIdentifier identifier = new ComponentIdentifier("x-test");
		assertThat(context.getComponentValue(null, identifier)).isEqualTo("Value1, Value2");
	}

	@Test
	void testGetHeaderComponentNotFound() throws SignatureException
	{
		when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap());
		final ComponentIdentifier identifier = new ComponentIdentifier("x-test");
		assertThat(context.getComponentValue(null, identifier)).isNull();
	}

	@Test
	void testGetSignatureHeader()
	{
		when(request.getHeader("Signature")).thenReturn("test-signature");
		assertThat(context.getSignatureHeader()).isEqualTo("test-signature");
	}

	@Test
	void testGetSignatureInputHeader()
	{
		when(request.getHeader("Signature-Input")).thenReturn("test-signature-input");
		assertThat(context.getSignatureInputHeader()).isEqualTo("test-signature-input");
	}
}
