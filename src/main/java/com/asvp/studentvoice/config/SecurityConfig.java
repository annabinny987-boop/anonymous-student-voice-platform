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

    /*
     * Password encoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
     * Load administrator credentials from environment variables.
     */
    @Bean
    public UserDetailsService userDetailsService(
            PasswordEncoder passwordEncoder) {

        String username = System.getenv("ASVP_ADMIN_USERNAME");
        String password = System.getenv("ASVP_ADMIN_PASSWORD");

        if (username == null || username.isBlank()
                || password == null || password.isBlank()) {

            throw new IllegalStateException(
                    "Admin credentials are missing. Configure "
                    + "ASVP_ADMIN_USERNAME and ASVP_ADMIN_PASSWORD "
                    + "in the deployment environment."
            );
        }

        UserDetails admin = User.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(admin);
    }

    /*
     * Configure authentication, authorization, CSRF and sessions.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http) throws Exception {

        http

            /*
             * Keep CSRF protection enabled.
             *
             * Exempt only the two public POST submission endpoints.
             * Login and administrative actions remain CSRF-protected.
             */
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

            /*
             * Authorization rules.
             *
             * Administrative endpoints are explicitly protected
             * before the public concern-tracking rule.
             */
            .authorizeHttpRequests(auth -> auth

                // Public website and login page
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/admin.html",
                    "/favicon.ico",
                    "/css/**",
                    "/js/**",
                    "/images/**"
                ).permitAll()

                // Public concern submission
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/concerns"
                ).permitAll()

                // Public emergency submission
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/emergency"
                ).permitAll()

                // CSRF token endpoint
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/csrf"
                ).permitAll()

                // Admin-only dashboard and management APIs
                .requestMatchers(
                    "/admin-dashboard.html",
                    "/api/concerns/admin",
                    "/api/concerns/admin/**",
                    "/api/emergency",
                    "/api/emergency/**"
                ).hasRole("ADMIN")

                // Public concern tracking
                .requestMatchers(
                    HttpMethod.GET,
                    "/api/concerns/*"
                ).permitAll()

                // All other endpoints require admin authorization
                .anyRequest().hasRole("ADMIN")
            )

            /*
             * Spring Security form login.
             *
             * admin.html must submit username and password
             * as a normal POST form to /login.
             */
            .formLogin(form -> form
                .loginPage("/admin.html")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl(
                    "/admin-dashboard.html",
                    true
                )
                .failureUrl("/admin.html?error")
                .permitAll()
            )

            /*
             * Logout
             */
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/admin.html?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )

            /*
             * Session fixation protection
             */
            .sessionManagement(session ->
                session.sessionFixation(fixation ->
                    fixation.migrateSession()
                )
            );

        return http.build();
    }
}