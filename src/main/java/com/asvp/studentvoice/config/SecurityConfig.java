package com.asvp.studentvoice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.Customizer;
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
                    "Admin credentials are missing. Set "
                    + "ASVP_ADMIN_USERNAME and ASVP_ADMIN_PASSWORD."
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
            // CSRF protection: exempt only public student submissions
            .csrf(csrf -> csrf
                .ignoringRequestMatchers(
                    request -> "POST".equals(request.getMethod())
                            && ("/api/concerns".equals(request.getServletPath())
                            || "/api/emergency".equals(request.getServletPath()))
                )
            )

            // Access permissions
            .authorizeHttpRequests(auth -> auth

                // Public website pages
                .requestMatchers(
                    "/",
                    "/index.html",
                    "/admin.html",
                    "/favicon.ico",
                    "/css/**",
                    "/js/**",
                    "/images/**"
                ).permitAll()

                // Students can submit concerns
                .requestMatchers(
                    HttpMethod.POST, "/api/concerns"
                ).permitAll()

                // Students can track concerns using their tracking codes
                .requestMatchers(
                    HttpMethod.GET, "/api/concerns/*"
                ).permitAll()

                // Students can submit emergency alerts
                .requestMatchers(
                    HttpMethod.POST, "/api/emergency"
                ).permitAll()

                // CSRF token endpoint
                .requestMatchers(
                    HttpMethod.GET, "/api/csrf"
                ).permitAll()

                // Admin dashboard
                .requestMatchers(
                    "/admin-dashboard.html"
                ).hasRole("ADMIN")

                // Everything else requires admin authentication
                .anyRequest().hasRole("ADMIN")
            )

            // Login
            .formLogin(form -> form
                .loginPage("/admin.html")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .defaultSuccessUrl("/admin-dashboard.html", true)
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

            // Session protection
            .sessionManagement(session ->
                session.sessionFixation(fixation ->
                    fixation.migrateSession()
                )
            );

        return http.build();
    }
}