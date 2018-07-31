package com.springbootsecurityback.dto;

import java.io.Serializable;

import org.springframework.security.core.userdetails.UserDetails;

public class LoginDTO implements Serializable{
	
	private static final long serialVersionUID = 8347170147895146226L;
	private String token;
	private UserDetails userDetails;

	public LoginDTO(String token, UserDetails userDetails) {
		super();
		this.token = token;
		this.userDetails = userDetails;
	}

	public LoginDTO() {
		super();
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public UserDetails getUserDetails() {
		return userDetails;
	}

	public void setUserDetails(UserDetails userDetails) {
		this.userDetails = userDetails;
	}

}
