package com.yash.booking.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.yash.booking.util.SecurityConstants;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	private TokenProvider jwtTokenUtil;

	private String userid = null;
	
	public String getUserid() {
		return userid;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException,UsernameNotFoundException {
		String header = req.getHeader(SecurityConstants.HEADER_STRING);
		String username = null;
		String authToken = null;
		
		if (header != null && header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			authToken = header.replace(SecurityConstants.TOKEN_PREFIX, "");
			try {
				username = jwtTokenUtil.getUsernameFromToken(authToken);
				setUserid(jwtTokenUtil.getUserIDFromToken(authToken));
			} catch (IllegalArgumentException e) {
				System.err.println("an error occured during getting username from token "+ e);
			} catch (ExpiredJwtException e) {
				System.err.println("the token is expired and not valid anymore"+ e);
			} catch (SignatureException e) {
				System.err.println("Authentication Failed. Username or Password not valid.");
				throw new UsernameNotFoundException("Username or Password not valid.");
				
			}
		} else {
			logger.warn("couldn't find bearer string, will ignore the header");
		}
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			
			if (jwtTokenUtil.validateToken(authToken, userDetails)) {
				UsernamePasswordAuthenticationToken authentication = jwtTokenUtil.getAuthentication(authToken,
						SecurityContextHolder.getContext().getAuthentication(), userDetails);
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
				logger.info("authenticated user " + username + ", setting security context");
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		chain.doFilter(req, res);
	}
}