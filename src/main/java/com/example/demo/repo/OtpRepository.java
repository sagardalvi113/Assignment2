package com.example.demo.repo;

import org.springframework.data.repository.CrudRepository;

import com.example.demo.model.Otp;
import com.example.demo.model.User;

public interface OtpRepository extends CrudRepository<Otp,Integer>{

	
	public Otp findByUserName(String userName) ;
}
