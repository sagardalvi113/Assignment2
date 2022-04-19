package com.example.demo.util;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
	
	
	private String secret="sagar";
	
	// 6 validate token
	
	public boolean validateToken(String token,String userName)
	{
		String tokenUserName=getUserName(token);
		return (userName.equals(tokenUserName) && !isTokenExp(token));
	}
	
	
	// 5 validate exp date
	
	public boolean isTokenExp(String token)
	{
		Date expDate = getExpDate(token);
		return expDate.before(new Date(System.currentTimeMillis()));
	}
	
	// 4 read subject/userName
	
	public String getUserName(String token)
	{
		return getClaims(token).getSubject();
	}
	
	//3  read exp date
	
	public Date getExpDate(String token)
	{
		return getClaims(token).getExpiration();
	}
	
	// 2 read claims
	
	public Claims getClaims(String token) 
	{
		return Jwts.parser().setSigningKey(secret.getBytes())
				.parseClaimsJws(token)
				.getBody();
	}
	
	public String generateToken(String userName)
	{
		return Jwts.builder()
				.setSubject(userName)
				.setIssuer("Sagar")
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15)))
				.signWith(SignatureAlgorithm.HS512,secret.getBytes())
				.compact();
	}

}
