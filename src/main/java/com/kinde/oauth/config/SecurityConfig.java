package com.kinde.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Security configuration class that sets up the security filters and OAuth2 login
 * configurations for the application. This class enables method-level security
 * and configures the security filter chain with necessary handlers.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final OidcLogoutHandler oidcLogoutHandler;

    /**
     * Constructs a SecurityConfig with the provided OidcLogoutHandler.
     *
     * @param oidcLogoutHandler the logout handler for OIDC authentication.
     */
    public SecurityConfig(OidcLogoutHandler oidcLogoutHandler) {
        this.oidcLogoutHandler = oidcLogoutHandler;
    }

    /**
     * Configures the security filter chain, setting up CORS, authorization rules,
     * OAuth2 resource server, and OAuth2 login with OIDC user service.
     * <p>
     * Note: If you wish to use configuration-based security instead of method-based security,
     * you can uncomment the relevant lines and specify roles or permissions directly here.
     * </p>
     *
     * @param http the HttpSecurity to modify.
     * @return the configured SecurityFilterChain.
     * @throws Exception if an error occurs during configuration.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**").permitAll()
                        .requestMatchers("/", "/home").permitAll()
                        // Uncomment the lines below to configure security based on roles or permissions
                        // .requestMatchers("/admin").hasRole("admins")
                        // .requestMatchers("/read").hasRole("read")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .oidcUserService(new CustomOidcUserService())
                        )
                );
        http
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/home")
                        .addLogoutHandler(oidcLogoutHandler)
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                );

        return http.build();
    }

    /**
     * Configures the JwtAuthenticationConverter to extract authorities from JWT claims.
     *
     * @return the configured JwtAuthenticationConverter.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(this::extractAuthoritiesFromClaims);
        return converter;
    }

    /**
     * Extracts authorities from the JWT claims, converting them to GrantedAuthority.
     *
     * @param jwt the JWT containing the claims.
     * @return a collection of GrantedAuthority extracted from the JWT claims.
     */
    private Collection<GrantedAuthority> extractAuthoritiesFromClaims(Jwt jwt) {
        var permissions = jwt.getClaimAsStringList("permissions");

        return permissions.stream()
                .map(permission -> new SimpleGrantedAuthority("ROLE_" + permission))
                .collect(Collectors.toList());
    }
}
