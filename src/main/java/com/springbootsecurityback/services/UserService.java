package com.springbootsecurityback.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.springbootsecurityback.dao.UserRepository;
import com.springbootsecurityback.entities.User;

/**
 * @author breymer.robles
 *
 */
@Service
public class UserService {

	@Autowired
	UserRepository userRepository;
	
	public User save(User user) {
		return userRepository.save(user);
	}

	public User update(User user) {
		return userRepository.save(user);
	}

	public User find(String userName) {
		return userRepository.findOneByUsername(userName);
	}
	
	
	public User findById(String id) {
		return userRepository.findById(id).map(u -> u).orElse(null);
	}
}
