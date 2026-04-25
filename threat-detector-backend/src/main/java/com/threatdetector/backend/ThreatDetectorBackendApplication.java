package com.threatdetector.backend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class ThreatDetectorBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatDetectorBackendApplication.class, args);
    }
}
