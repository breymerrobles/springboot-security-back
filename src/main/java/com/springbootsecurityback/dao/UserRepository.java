package com.springbootsecurityback.dao;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.springbootsecurityback.entities.User;

/* this the user  Repository interface  */ 
@Repository
public interface UserRepository extends MongoRepository<User, String> {

public User findOneByUsername(String username);

}
