package com.asvp.studentvoice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder passwordEncoder) {

        String username = System.getenv("ASVP_ADMIN_USERNAME");
        String password = System.getenv("ASVP_ADMIN_PASSWORD");

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {
            throw new IllegalStateException(
                    "Set ASVP_ADMIN_USERNAME and ASVP_ADMIN_PASSWORD "
                    + "in the Render environment variables."
            );
        }

        UserDetails admin = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests(auth -> auth

                // Public student website
                .requestMatchers(
                        "/",
                        "/index.html",
                        "/favicon.ico",
                        "/css/**",
                        "/js/**",
                        "/images/**"
                ).permitAll()

                // Public admin login page
                .requestMatchers(
                        "/admin.html",
                        "/api/csrf"
                ).permitAll()

                // Students may submit anonymous concerns
                .requestMatchers(
                        HttpMethod.POST,
                        "/api/concerns"
                ).permitAll()

                // Students may track a concern by tracking code
                .requestMatchers(
                        HttpMethod.GET,
                        "/api/concerns/*"
                ).permitAll()

                // Students may submit emergency alerts
                .requestMatchers(
                        HttpMethod.POST,
                        "/api/emergency"
                ).permitAll()

                // Admin dashboard requires authentication
                .requestMatchers(
                        "/admin-dashboard.html"
                ).hasRole("ADMIN")

                // All other endpoints require administrator access
                .anyRequest().hasRole("ADMIN")
            )

            // Keep CSRF protection enabled.
            // Exempt only the public student submission endpoints.
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    request ->
                        "POST".equals(request.getMethod())
                        && (
                            "/api/concerns".equals(
                                request.getServletPath()
                            )
                            ||
                            "/api/emergency".equals(
                                request.getServletPath()
                            )
                        )
                )
            )

            // Administrator login
            .formLogin(form -> form
                .loginPage("/admin.html")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/admin-dashboard.html", true)
                .failureUrl("/admin.html?error")
                .permitAll()
            )

            // Administrator logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/admin.html?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )

            // Protect against session fixation
            .sessionManagement(session ->
                session.sessionFixation(fixation ->
                    fixation.migrateSession()
                )
            );

        return http.build();
    }
}