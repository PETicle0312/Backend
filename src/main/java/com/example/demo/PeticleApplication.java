package com.example.demo;

import com.example.demo.game.service.PointService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;

@SpringBootApplication(exclude = org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class)
@EntityScan(basePackages = "com.example.demo")
public class PeticleApplication  {
    public static void main(String[] args) {
        SpringApplication.run(PeticleApplication.class, args);
    }
}
