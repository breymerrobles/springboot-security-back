package com.springbootsecurityback.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:config.properties")

/*
 * @PropertySource({ "classpath:persistence-${envTarget:mysql}.properties" })
 */
public class ConfigLoad {
	@Value("${cross.reference.url}")
	private String jdbcUrl;
	
	
	

}
