package co.daviplata.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class TokenGeneratorLambda implements RequestHandler<Map<String, Object>, Map<String, Object>> {

	private static final String ISSUER = "https://auth.daviplata.com";
	private static final String KID = "daviplata-key-001";
	private static final ObjectMapper mapper = new ObjectMapper();

	@Override
	@SuppressWarnings("unchecked")
	public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
		try {
			Map<String, Object> requestContext = (Map<String, Object>) event.get("requestContext");
			Map<String, Object> http = (Map<String, Object>) requestContext.get("http");
			String path = ((String) http.get("path")).toLowerCase();
			String method = ((String) http.get("method")).toUpperCase();

			if (path.equals("/oauth2/token") && method.equals("POST")) {
				return generateToken(event);
			} else {
				return response(404, Map.of("error", "Not found"));
			}

		} catch (Exception e) {
			return response(500, Map.of("error", e.getMessage()));
		}
	}

	private Map<String, Object> generateToken(Map<String, Object> event) throws Exception {
		Map<String, String> headers = (Map<String, String>) event.get("headers");
		String authHeader = headers.getOrDefault("authorization", headers.getOrDefault("Authorization", ""));

		if (!authHeader.startsWith("Basic ")) {
			return response(401, Map.of("error", "Missing or invalid Authorization header"));
		}

		String[] creds = new String(Base64.getDecoder().decode(authHeader.substring(6))).split(":");
		if (creds.length != 2 || !isValidClient(creds[0], creds[1])) {
			return response(403, Map.of("error", "Invalid client credentials"));
		}

		boolean isBase64Encoded = Boolean.TRUE.equals(event.get("isBase64Encoded"));
		String rawBody = (String) event.get("body");
		if (isBase64Encoded && rawBody != null) {
			rawBody = new String(Base64.getDecoder().decode(rawBody), StandardCharsets.UTF_8);
		}

		System.out.println("RAW BODY (decoded if needed): " + rawBody);

		Map<String, String> form = parseFormEncoded(rawBody);

		System.out.println("PARSED FORM:");
		form.forEach((k, v) -> System.out.println("  " + k + " = " + v));

		String grantType = form.getOrDefault("grant_type", "").trim().toLowerCase();
		if (!grantType.equals("client_credentials")) {
			return response(400, Map.of("error", "Unsupported grant_type"));
		}

		String scope = form.getOrDefault("scope", "https://default.scope");
		long now = System.currentTimeMillis();
		long exp = now + 3600 * 1000;

		Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) loadPrivateKey());
		String jwt = JWT.create().withKeyId(KID).withIssuer(ISSUER).withSubject(UUID.randomUUID().toString())
				.withAudience("care-client-id").withClaim("token_use", "access").withClaim("scope", scope)
				.withClaim("auth_time", now / 1000).withClaim("version", 2).withJWTId(UUID.randomUUID().toString())
				.withIssuedAt(new Date(now)).withExpiresAt(new Date(exp)).sign(algorithm);

		return response(200, Map.of("access_token", jwt, "token_type", "Bearer", "expires_in", 3600));
	}

	private Map<String, String> parseFormEncoded(String body) {
		Map<String, String> form = new HashMap<>();
		if (body == null || body.trim().isEmpty())
			return form;

		String[] pairs = body.split("&");
		for (String pair : pairs) {
			int idx = pair.indexOf('=');
			if (idx > 0 && idx < pair.length() - 1) {
				String key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
				String value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
				form.put(key, value);
			}
		}

		return form;
	}

	private boolean isValidClient(String clientId, String clientSecret) {
		return clientId.equals("mi-client-id") && clientSecret.equals("mi-client-secret");
	}

	private PrivateKey loadPrivateKey() throws Exception {
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("private_key.pem")) {
			if (is == null)
				throw new IllegalStateException("No se encontró private_key.pem");
			byte[] pem = is.readAllBytes();
			String key = new String(pem).replaceAll("-----BEGIN ([A-Z ]+)-----", "")
					.replaceAll("-----END ([A-Z ]+)-----", "").replaceAll("\\s+", "");
			byte[] decoded = Base64.getDecoder().decode(key);
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
		}
	}

	private Map<String, Object> response(int code, Map<String, Object> body) {
		return Map.of("statusCode", code, "headers", Map.of("Content-Type", "application/json"), "body", toJson(body));
	}

	private String toJson(Map<String, Object> map) {
		try {
			return mapper.writeValueAsString(map);
		} catch (Exception e) {
			return "{\"error\":\"JSON error\"}";
		}
	}
}