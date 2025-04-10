package com.example.demo33;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@ServletComponentScan
@SpringBootApplication
public class Demo33Application {

    public static void main(String[] args) {
        SpringApplication.run(Demo33Application.class, args);
    }

}
