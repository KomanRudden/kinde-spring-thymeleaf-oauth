package com.kinde.oauth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Objects;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Slf4j
public class SecurityConfig {

    private final OidcLogoutHandler oidcLogoutHandler;

    public SecurityConfig(OidcLogoutHandler oidcLogoutHandler) {
        this.oidcLogoutHandler = oidcLogoutHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/css/**").permitAll()
                        .requestMatchers("/", "/home").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .oauth2Login(withDefaults());
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
     * Configures a {@link JwtAuthenticationConverter} to extract and convert the "permissions" claim
     * from a {@link Jwt} token into a collection of {@link GrantedAuthority} objects.
     *
     * <p>This method is invoked during the JWT authentication process in a Spring Security
     * application. Specifically, it runs when a JWT is being decoded and validated as part
     * of the authentication process, converting the permissions contained in the JWT into
     * appropriate roles recognized by the application.</p>
     *
     * <p>The {@link JwtAuthenticationConverter} created by this method will:
     * <ul>
     *   <li>Extract the "permissions" claim from the JWT.</li>
     *   <li>Map each permission to a corresponding {@link SimpleGrantedAuthority}:
     *     <ul>
     *       <li>"admin" is mapped to "ROLE_ADMIN".</li>
     *       <li>"read" is mapped to "ROLE_USER".</li>
     *     </ul>
     *   </li>
     *   <li>Ignore any permissions that do not match the expected values.</li>
     * </ul>
     * </p>
     *
     * <p>This method is typically used in a {@link SecurityConfigurerAdapter} to customize
     * the JWT authentication process, ensuring that users are granted the correct authorities
     * based on the claims present in their JWT.</p>
     *
     * @return a configured {@link JwtAuthenticationConverter} that maps JWT permissions to Spring Security roles.
     */
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> jwt.getClaimAsStringList("permissions")
                .stream()
                .map(permission -> {
                    if ("admin".equals(permission)) {
                        System.out.println("ADMIN");
                        return new SimpleGrantedAuthority("ROLE_ADMIN");
                    } else if ("read".equals(permission)) {
                        System.out.println("READ");
                        return new SimpleGrantedAuthority("ROLE_USER");
                    } else {
                        System.out.println("NULL");
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList()));
        return converter;
    }
}
