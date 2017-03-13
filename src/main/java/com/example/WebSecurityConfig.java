package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // enabling the authorization check before each service call.
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AzureAdJwtAuthenticationTokenFilter azureAdJwtAuthenticationTokenFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // allow access if we stored our front-end pages in the same project.
        // if the static pages are hosted somewhere else, ignore this line.
        http.authorizeRequests().antMatchers("/").permitAll();

        // we only host RESTful API and every services are protected.
        http.authorizeRequests().anyRequest().authenticated();

        // we are using token based authentication. csrf is not required.
        http.csrf().disable();

        // need a filter to validate the Jwt token from AzureAD and assign roles.
        // without this, the token will not be validated and the role is always ROLE_USER.
        http.addFilterBefore(azureAdJwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);
        
        // the following code handle preflight messages so ajax calls will work...

        // prepare cors config
        CorsConfiguration corsConfig = new CorsConfiguration();
        
        // Access-Control-Allow-Origin: *
        corsConfig.addAllowedOrigin("*");
        
        // Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
        corsConfig.addAllowedMethod(HttpMethod.GET);
        corsConfig.addAllowedMethod(HttpMethod.POST);
        corsConfig.addAllowedMethod(HttpMethod.PUT);
        corsConfig.addAllowedMethod(HttpMethod.DELETE);
        corsConfig.addAllowedMethod(HttpMethod.OPTIONS);
        
        // Access-Control-Max-Age: 3600
        corsConfig.setMaxAge(3600L);
        
        // Access-Control-Allow-Headers: authorization, content-type, xsrf-token
        corsConfig.addAllowedHeader("authorization");
        corsConfig.addAllowedHeader("content-type");
        corsConfig.addAllowedHeader("xsrf-token");
        
        // Access-Control-Expose-Headers: xsrf-token
        corsConfig.addExposedHeader("xsrf-token");
        
        // ant match any request path to apply this policy.
        UrlBasedCorsConfigurationSource corsConfigSource = new UrlBasedCorsConfigurationSource();
        corsConfigSource.registerCorsConfiguration("/**", corsConfig);

        // this is required to handle preflight message...
        http.addFilterBefore(new CorsFilter(corsConfigSource), ChannelProcessingFilter.class);
    }
}
