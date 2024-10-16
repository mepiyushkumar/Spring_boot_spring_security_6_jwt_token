package com.example.spring_security_jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Autowired
    public UserDetailsService userDetailsService;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(5);
    }


    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
//                .cors(cors -> cors.configurationSource(request -> {
//                    CorsConfiguration config = new CorsConfiguration();
//                    config.addAllowedOrigin("https:www.google.com");
//                    config.setAllowedMethods(Arrays.asList("GET", "POST")); // Allow GET and POST methods
//                    config.setAllowedHeaders(List.of("Authorization", "Content-Type")); // Allow specific headers
//                    config.setAllowCredentials(true); // Allow credentials like cookies, authorization headers
//                    return config;
//                }))
                .csrf(csrf -> csrf.disable()).authorizeHttpRequests(request -> request.
                        requestMatchers("/create").permitAll().
                        requestMatchers("/login").permitAll().anyRequest().authenticated())
//        .formLogin(Customizer.withDefaults())
                // Enables HTTP Basic authentication (useful for testing APIs) alongside JWT
                .httpBasic(Customizer.withDefaults())

                // Configures session management to be stateless (no sessions created)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Adds a custom JWT filter that handles token validation before UsernamePasswordAuthenticationFilter

                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    //without db data
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1  =  User
//                .withDefaultPasswordEncoder()
//                .username("q")
//                .password("q")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1);
//
//    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        //what ever i password we get convert into Bcrypt and check
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}
