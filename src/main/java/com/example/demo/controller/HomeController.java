package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.LoginResponse;
import com.example.demo.model.Otp;
import com.example.demo.model.RegisterResponse;
import com.example.demo.model.User;
import com.example.demo.model.Verifier;
import com.example.demo.responce.Responce;
import com.example.demo.userservice.UserService;
import com.example.demo.util.JwtUtil;

@RestController
public class HomeController {

	@Autowired
	private UserService userService;
	
	@Autowired
	private JwtUtil jwtutil;
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@PostMapping("/loginUser")
	public LoginResponse login(@RequestBody User user) {
		
		String string = userService.login(user);
		
		LoginResponse loginResponse=new LoginResponse();
		

		loginResponse.setMessage(string);
		loginResponse.setUsername(user.getUserName());
		
		
		if(string.startsWith("Welcome"))
		{
			String token=jwtutil.generateToken(user.getUserName());
			loginResponse.setToken(token);
			
			
			 
			return loginResponse;
		}
		
		return loginResponse;

	}

	@PostMapping("/registerUser")
	public ResponseEntity<RegisterResponse> registerDatabase(@RequestBody User user) {

		String string = userService.register(user);
		
		RegisterResponse registerResponse=new RegisterResponse(user, string);
		
		return new ResponseEntity<RegisterResponse>(registerResponse, HttpStatus.OK);

	}
	
	@PostMapping("/verifyUser")
	public Responce verifyUser(@RequestBody Verifier verifier) {
		
	
		
		String string=userService.verifyUser(verifier);
		
		Responce responce = new Responce();
		responce.setMessage(string);
		return responce;
		
	}
	@GetMapping("/hello")
	public String hello()
	{
		return "hello";
	}

}
