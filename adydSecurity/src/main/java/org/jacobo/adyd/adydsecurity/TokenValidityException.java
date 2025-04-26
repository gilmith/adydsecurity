package org.jacobo.adyd.adydsecurity;

import com.auth0.jwt.exceptions.*;

public class TokenValidityException extends RuntimeException {

	public TokenValidityException(AlgorithmMismatchException e) {
		// TODO Auto-generated constructor stub
	}

	public TokenValidityException(SignatureVerificationException e) {
		// TODO Auto-generated constructor stub
	}

	public TokenValidityException(InvalidClaimException e) {
		// TODO Auto-generated constructor stub
	}

	public TokenValidityException(TokenExpiredException e) {
		// TODO Auto-generated constructor stub
	}

	public TokenValidityException(JWTDecodeException e) {
		// TODO Auto-generated constructor stub
	}

}
