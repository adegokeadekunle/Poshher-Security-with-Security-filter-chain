package com.adekunle.springsecuritywithfilterchain.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/security")
public class SecurityController {

    @GetMapping("/secure")
    public String message( ) {
        return "Security Login is Successful";
    }
}
