package com.briller;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import javax.annotation.PostConstruct;
import java.util.Date;
import java.util.TimeZone;

@SpringBootApplication
@EnableJpaAuditing
public class FtdcQuestionaireAppApplication {

	@PostConstruct
	public void init(){
		TimeZone.setDefault(TimeZone.getTimeZone("America/Nassau"));
		System.out.println("Spring boot application running in IST timezone :"+new Date());
	}

	public static void main(String[] args) {

		SpringApplication.run(FtdcQuestionaireAppApplication.class, args);
	}

}
