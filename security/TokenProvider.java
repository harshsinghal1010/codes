
package com.yash.booking.security;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.yash.booking.beans.User;
import com.yash.booking.dao.UserRepository;
import com.yash.booking.util.SecurityConstants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;



@Component
public class TokenProvider implements Serializable {
	
	@Autowired
	private UserRepository repo;

	private static final long serialVersionUID = -5865364131878714415L;

	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
		
		
	}
	
	public String getUserIDFromToken(String token) {
		final Claims claims = getAllClaimsFromToken(token);
		return claims.get("UserId").toString();
	}


	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(SecurityConstants.SIGNING_KEY).parseClaimsJws(token).getBody();
	}

	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	public String generateToken(Authentication authentication) {
		String  email =  authentication.getName();
		User user =  repo.findByEmailAndDeletedFalse(email);
		final String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		return Jwts.builder().setSubject(email)
				.claim(SecurityConstants.AUTHORITIES_KEY, authorities)
				.claim(SecurityConstants.USER_KEY, user != null ? user.getUserId() : null)
				.signWith(SignatureAlgorithm.HS256, SecurityConstants.SIGNING_KEY)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * SecurityConstants.ACCESS_TOKEN_VALIDITY_SECONDS))
				.compact();
	}


	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	UsernamePasswordAuthenticationToken getAuthentication(final String token, final Authentication existingAuth,
			final UserDetails userDetails) {

		final JwtParser jwtParser = Jwts.parser().setSigningKey(SecurityConstants.SIGNING_KEY);

		final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);

		final Claims claims = claimsJws.getBody();

		final Collection<? extends GrantedAuthority> authorities = Arrays
				.stream(claims.get(SecurityConstants.AUTHORITIES_KEY).toString().split(",")).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
	}

}

