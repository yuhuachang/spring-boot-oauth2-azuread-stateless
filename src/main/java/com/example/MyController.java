package com.example;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// our services are stateless and can be called from anywhere.
@CrossOrigin
@RestController
public class MyController {

    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    @RequestMapping("/principal")
    public Principal principal(Principal principal) {
        return principal;
    }
    
    @PreAuthorize("hasRole('ROLE_USER')")
    @GetMapping("/users")
    public Map<String, Object> users() {
        Map<String, Object> response = new HashMap<>();
        response.put("content", "I have users permission");
        return response;
    }
    
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public Map<String, Object> admin() {
        Map<String, Object> response = new HashMap<>();
        response.put("content", "I have admin permission");
        return response;
    }
}
