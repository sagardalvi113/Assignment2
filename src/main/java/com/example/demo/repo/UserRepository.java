package com.example.demo.repo;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.example.demo.model.User;

@Repository
public interface UserRepository extends CrudRepository<User,Integer>{
	
	
	// custom finder methods 
	public User findByUserName(String userName) ;
	
	public User findByEmailId(String emailId) ;

}
