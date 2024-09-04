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
        OidcUser oidcUser = super.loadUser(userRequest);
        String accessToken = userRequest.getAccessToken().getTokenValue();
        Jwt jwt = parseJwtToken(accessToken);
        Collection<GrantedAuthority> authorities = extractAuthoritiesFromJwt(jwt);

        return new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
    }

    private Jwt parseJwtToken(String token) {
        return Jwt.withTokenValue(token)
                .header("alg", "none")
                .claim("permissions", List.of("read", "admin"))
                .build();
    }

    private Collection<GrantedAuthority> extractAuthoritiesFromJwt(Jwt jwt) {
        List<String> permissions = jwt.getClaimAsStringList("permissions");

        // Convert permissions to Spring Security roles
        return permissions.stream()
                .map(permission -> new SimpleGrantedAuthority("ROLE_" + permission))
                .collect(Collectors.toList());
    }
}

