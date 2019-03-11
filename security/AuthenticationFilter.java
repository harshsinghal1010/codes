package com.yash.booking.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yash.booking.beans.User;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;

	public AuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	// First this one is called during login - STEP-1
	@Override
	public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res)
			throws AuthenticationException {
		try {

			User creds = new ObjectMapper().readValue(req.getInputStream(), User.class);

			return authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getPassword(), new ArrayList<>()));

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	// Step-2 --- If password is not correct then then will not be called.
	@Override
	protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain,
			Authentication auth) throws IOException, ServletException {
		
		final String authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
		String userName = ((User) auth.getPrincipal()).getName();
		
		String token = Jwts.builder().setSubject(userName).claim("ROLES", authorities)
				.setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SecurityConstants.TOKEN_SECRET).compact();
		JwtTokenContainer jwtTokenContainer = JwtTokenContainer.getInstance();
		ConcurrentMap<String, String> generatedTokenMap=jwtTokenContainer.getSeesionTokenList();
		generatedTokenMap.put(token, "valid");
		res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);

	}

}
