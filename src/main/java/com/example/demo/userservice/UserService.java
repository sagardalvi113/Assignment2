package com.example.demo.userservice;

import org.springframework.stereotype.Service;

import com.example.demo.model.Otp;
import com.example.demo.model.User;
import com.example.demo.model.Verifier;
@Service
public interface UserService {

	
	public String register(User user);
	
	public String login(User user);

	public String verifyUser(Verifier verifier);
	
	
	
}
