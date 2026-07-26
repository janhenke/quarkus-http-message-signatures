package dev.janhenke.quarkus.http.message.signatures.runtime;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.SignatureContext;
import com.authlete.hms.SignatureMetadata;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import java.security.SignatureException;
import java.util.List;
import java.util.Locale;

/**
 * Vert.x implementation of {@link SignatureContext}.
 *
 * @author Jan Henke
 */
@RequestScoped
public class VertxSignatureContext implements SignatureContext
{
	private final RoutingContext routingContext;
	private final HttpServerRequest request;

	@Inject
	public VertxSignatureContext(@Nonnull final RoutingContext routingContext)
	{
		this.routingContext = routingContext;
		request = routingContext.request();
	}

	@Override
	public String getComponentValue(final SignatureMetadata metadata, @Nonnull final ComponentIdentifier identifier)
			throws SignatureException
	{
		if (identifier.isDerivedComponent())
		{
			return getDerivedComponentValue(identifier);
		}
		return getHeaderComponentValue(identifier);
	}

	private String getDerivedComponentValue(@Nonnull final ComponentIdentifier identifier) throws SignatureException
	{
		final String componentName = identifier.getComponentName();
		return switch (componentName)
		{
			case "@method" -> request.method().name();
			case "@target-uri" -> request.absoluteURI();
			case "@authority" ->
			{
				final String host = request.authority().host().toLowerCase(Locale.ROOT);
				final int port = request.authority().port();
				final String scheme = request.scheme();

				// RFC 9421: Port MUST be excluded if it is the default for the scheme
				final boolean isDefaultPort = (scheme.equalsIgnoreCase("http") && port == 80)
						|| (scheme.equalsIgnoreCase("https") && port == 443);

				if (port < 0 || isDefaultPort)
				{
					yield host;
				}
				yield host + ":" + port;
			}
			case "@scheme" -> request.scheme();
			case "@request-target" -> request.uri();
			case "@path" -> request.path();
			case "@query" ->
			{
				final String query = request.query();
				// RFC 9421: Include '?' if present, return empty string if no query component
				yield (query == null || query.isEmpty()) ? "" : "?" + query;
			}
			case "@query-param" ->
			{
				final String paramName = identifier.getParameters().getName();
				if (paramName == null)
				{
					throw new SignatureException("@query-param component missing 'name' parameter");
				}
				// Use routingContext.queryParams() to specifically target query string parameters
				final String value = routingContext.queryParams().get(paramName);
				if (value == null)
				{
					throw new SignatureException("Query parameter '" + paramName + "' not found");
				}
				yield value;
			}
			default -> throw new SignatureException("Unsupported derived component: " + componentName);
		};
	}

	@Nullable
	private String getHeaderComponentValue(@Nonnull final ComponentIdentifier identifier)
	{
		final String headerName = identifier.getComponentName();
		final List<String> values = request.headers().getAll(headerName);

		if (values == null || values.isEmpty())
		{
			// Returning null allows the Authlete library to handle missing required components
			return null;
		}

		// RFC 9421 Section 2.1: Multiple instances of the same header are joined with ", "
		return String.join(", ", values);
	}

	public String getSignatureHeader()
	{
		return request.getHeader("Signature");
	}

	public String getSignatureInputHeader()
	{
		return request.getHeader("Signature-Input");
	}
}
