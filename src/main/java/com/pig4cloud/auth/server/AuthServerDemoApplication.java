package com.pig4cloud.auth.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class AuthServerDemoApplication {

	public static void main(String[] args) {
		ApplicationContext context =SpringApplication.run(AuthServerDemoApplication.class, args);


	}

}
