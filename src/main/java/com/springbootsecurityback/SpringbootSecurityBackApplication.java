package com.springbootsecurityback;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

import com.springbootsecurityback.security.CsrfHeaderFilter;
import com.springbootsecurityback.security.JwtAuthenticationFilter;

@SpringBootApplication
@ComponentScan(basePackages = { "com.springbootsecurityback" })
public class SpringbootSecurityBackApplication {
	@Value("${app.security.script.strength}")
	private int scriptStrength;
	@Value("${app.security.script.strength}")
	private String adminRoutes;

	public static void main(String[] args) {
		SpringApplication.run(SpringbootSecurityBackApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(4);
		for (int i = 0; i < 5; i++) {
			// "123456" - plain text - user input from user interface
			String passwd = bCryptPasswordEncoder.encode("123456");

			// passwd - password from database
			System.out.println(passwd); // print hash

			// true for all 5 iteration
			System.out.println(bCryptPasswordEncoder.matches("123456", passwd));
		}
		return bCryptPasswordEncoder;
	}

	@Bean
	public JwtAuthenticationFilter jwtAuthenticationFilter() {
		return new JwtAuthenticationFilter();
	}

	@Bean
	public CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setHeaderName("X-XSRF-TOKEN");
		return repository;

	}

	@Bean
	public CsrfHeaderFilter csrfHeaderFilter() {
		return new CsrfHeaderFilter();

	}

}
