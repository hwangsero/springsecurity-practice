package com.cos.securityex01;

import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Securityex01Application {

	public static void main(String[] args) {
		SpringApplication.run(Securityex01Application.class, args);
	}

}
