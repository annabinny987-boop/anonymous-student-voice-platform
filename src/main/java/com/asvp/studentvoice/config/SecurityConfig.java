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

                // Public homepage and static resources
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/favicon.ico",
                    "/css/**",
                    "/js/**",
                    "/images/**"
                ).permitAll()

                // Public student APIs
                .requestMatchers(
                    HttpMethod.POST, "/api/concerns"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET, "/api/concerns/*"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.POST, "/api/emergency"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET, "/api/csrf"
                ).permitAll()

                // Admin login page
                .requestMatchers(
                    "/admin.html",
                    "/login",
                    "/error"
                ).permitAll()

                // All other requests require admin authentication.
                // This includes the admin dashboard and admin APIs.
                .anyRequest().hasRole("ADMIN")
            )

            // Protect state-changing requests with CSRF.
            // Exempt only the two public student submission endpoints.
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    request ->
                        "POST".equals(request.getMethod())
                        && (
                            "/api/concerns".equals(
                                request.getServletPath()
                            )
                            || "/api/emergency".equals(
                                request.getServletPath()
                            )
                        )
                )
            )

            // Admin login
            .formLogin(form -> form
                .loginPage("/admin.html")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl(
                    "/admin-dashboard.html", true
                )
                .failureUrl("/admin.html?error")
                .permitAll()
            )

            // Logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/admin.html?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )

            // Protect the administrator's session
            .sessionManagement(session ->
                session.sessionFixation(fixation ->
                    fixation.migrateSession()
                )
            );

        return http.build();
    }
}