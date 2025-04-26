package org.jacobo.adyd.adydsecurity;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.base.Strings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;


@Component
@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {


	
	@Value("${secret}") 
	private String secret;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if(request.getRequestURI().startsWith("/api/bbdd/actuator") || request.getRequestURI().startsWith("/fav")
				||  request.getRequestURI().contains ("v3")
		|| request.getRequestURI().contains("swagger")){
			filterChain.doFilter(request, response);
			return;
		}
		
		if(request.getMethod().equals(HttpMethod.OPTIONS.name())) {
			filterChain.doFilter(request, response);
			return;
		}	
		val requestTokenHeader = request.getHeader("Authorization").substring(7);

	        if (Strings.isNullOrEmpty(requestTokenHeader)) {
	            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "log first");
	        }
	        try {
	        	val jwt = validateToken(requestTokenHeader);
	        	val username = jwt.getSubject();
	        	UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
	                    username, null, null);
	            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
	        	filterChain.doFilter(request, response);
	        } catch (AlgorithmMismatchException e) {
	            log.error("Wrong algorithm. The algorithm used does not match the corresponding one in the token header");
	            throw new TokenValidityException(e);
	        } catch (SignatureVerificationException e) {
	            log.error("Invalid signature. The value of secret is incorrect");
	            throw new TokenValidityException(e);
	        } catch (InvalidClaimException e) {
	            log.error("Wrong audience. Required audiences are missing");
	            throw new TokenValidityException(e);
	        } catch (JWTDecodeException e) {
	            if (e.getMessage().contains("token was expected")) {
	                log.error("JWT decoding failed. The token does not contain the necessary three distinct parts.");
		            throw new TokenValidityException(e);

	            } else {
	                log.error("Invalid decoding. The token format is incorrect.");
	            }
	        } catch (TokenExpiredException e) {
	            log.error(e.getMessage());
	            throw new TokenValidityException(e);
	        }

	}

	private DecodedJWT validateToken(String requestTokenHeader) {
		JWTVerifier verifier = JWT.require(Algorithm.HMAC384(secret)).build();
		return verifier.verify(requestTokenHeader);
		
	}

}
