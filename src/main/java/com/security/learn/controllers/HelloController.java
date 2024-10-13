package com.security.learn.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/")
    public String greet() {
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String greet1() {
        return "Hello User !";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String greet2() {
        return "Hello Admin !";
    }
}
