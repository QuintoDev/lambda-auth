package co.daviplata.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class JwtAuthorizerLambda implements RequestHandler<Map<String, Object>, Map<String, Object>> {

	private static final String ISSUER = "https://auth.daviplata.com";
	private static final String AUDIENCE = "care-client-id";

	@Override
	@SuppressWarnings("unchecked")
	public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
		try {
			String tokenRaw = null;

			if (event.containsKey("authorizationToken")) {
				tokenRaw = (String) event.get("authorizationToken");
			} else if (event.containsKey("headers")) {
				Map<String, String> headers = (Map<String, String>) event.get("headers");
				tokenRaw = headers.getOrDefault("authorization", headers.getOrDefault("Authorization", null));
			}

			if (tokenRaw == null || !tokenRaw.startsWith("Bearer ")) {
				System.out.println("Authorization header missing or malformed");
				return generatePolicy("unauthorized", "Deny", event.getOrDefault("methodArn", "*").toString());
			}

			// 2. Extraer método ARN
			String methodArn = event.getOrDefault("methodArn", "*").toString();

			// 3. Validar JWT
			String token = tokenRaw.replace("Bearer ", "").trim();
			Algorithm algorithm = Algorithm.RSA256(loadPublicKey(), null);
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(ISSUER).withAudience(AUDIENCE).build();

			DecodedJWT jwt = verifier.verify(token);
			System.out.println("Token válido: " + jwt.getSubject());

			return generatePolicy(jwt.getSubject(), "Allow", methodArn);

		} catch (JWTVerificationException e) {
			System.out.println("Token inválido: " + e.getMessage());
			return generatePolicy("unauthorized", "Deny", event.getOrDefault("methodArn", "*").toString());

		} catch (Exception e) {
			System.out.println("ERROR FATAL: " + e.getMessage());
			return generatePolicy("error", "Deny", event.getOrDefault("methodArn", "*").toString());
		}
	}

	private Map<String, Object> generatePolicy(String principalId, String effect, String methodArn) {
		Map<String, Object> statement = Map.of("Action", "execute-api:Invoke", "Effect", effect, "Resource", methodArn);

		Map<String, Object> policyDocument = Map.of("Version", "2012-10-17", "Statement", List.of(statement));

		return Map.of("principalId", principalId, "policyDocument", policyDocument);
	}

	private RSAPublicKey loadPublicKey() throws Exception {
		try (InputStream is = getClass().getClassLoader().getResourceAsStream("public_key.pem")) {
			byte[] pem = is.readAllBytes();
			String key = new String(pem).replaceAll("-----BEGIN ([A-Z ]+)-----", "")
					.replaceAll("-----END ([A-Z ]+)-----", "").replaceAll("\\s+", "");
			byte[] decoded = Base64.getDecoder().decode(key);
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
		}
	}
}