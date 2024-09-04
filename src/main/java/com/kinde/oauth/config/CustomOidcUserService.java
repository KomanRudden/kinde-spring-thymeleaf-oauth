package com.kinde.oauth.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomOidcUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) {
        // Call the parent method to load the OidcUser
        OidcUser oidcUser = super.loadUser(userRequest);

        // Extract the access token from the OidcUserRequest
        String accessToken = userRequest.getAccessToken().getTokenValue();

        // Parse the JWT token to get the permissions
        Jwt jwt = parseJwtToken(accessToken);

        // Extract authorities from JWT claims
        Collection<GrantedAuthority> authorities = extractAuthoritiesFromJwt(jwt);

        // Return a new OidcUser with custom authorities
        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private Jwt parseJwtToken(String token) {
        // This method should parse the JWT token. Depending on your setup, you might use a library or a custom implementation.
        // Example implementation might use Nimbus JWT library or another JWT parser.
        return Jwt.withTokenValue(token)
                .header("alg", "none")  // This is just an example; adjust based on actual JWT header
                .claim("permissions", List.of("read", "admin"))  // Adjust according to actual claims
                .build();
    }

    private Collection<GrantedAuthority> extractAuthoritiesFromJwt(Jwt jwt) {
        // Extract roles or permissions from the JWT claims
        List<String> permissions = jwt.getClaimAsStringList("permissions"); // Adjust the claim name if needed

        // Convert permissions to Spring Security roles
        return permissions.stream()
                .map(permission -> new SimpleGrantedAuthority("ROLE_" + permission))
                .collect(Collectors.toList());
    }
}

