package com.yash.booking.security;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class JwtTokenContainer {

	private static final JwtTokenContainer instance = new JwtTokenContainer();
	private final ConcurrentMap<String, String> seesionTokenList = new ConcurrentHashMap<String, String>();

	public static JwtTokenContainer getInstance() {
		return instance;
	}

	public ConcurrentMap<String, String> getSeesionTokenList() {
		return seesionTokenList;
	}

}
