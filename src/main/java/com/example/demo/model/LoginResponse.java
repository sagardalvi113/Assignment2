package com.example.demo.model;

public class LoginResponse 
{
	private String username;
	private String token;
	private String message;
	
	
	public LoginResponse() {
		super();
		// TODO Auto-generated constructor stub
	}
	public LoginResponse(String username, String token, String message) {
		super();
		this.username = username;
		this.token = token;
		this.message = message;
	}
	
	
	
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
}
