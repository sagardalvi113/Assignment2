package com.example.demo.model;

public class RegisterResponse {

	private String firstName;
	private String lastName;
	private String emailId;
	private String userName;
	private String message;
	
	public  RegisterResponse(User user,String message)
	{
		this.message=message;
		this.firstName=user.getFirstName();
		this.lastName=user.getLastName();
		this.emailId=user.getEmailId();
		this.userName=user.getUserName();
		
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmailId() {
		return emailId;
	}

	public void setEmailId(String emailId) {
		this.emailId = emailId;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
	
	
	
}
