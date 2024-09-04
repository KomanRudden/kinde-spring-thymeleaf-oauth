package com.kinde.oauth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

@Component
public class OidcLogoutHandler implements LogoutHandler {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public OidcLogoutHandler(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @SneakyThrows
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken oauthToken) {

            // Remove the OAuth2AuthorizedClient
            authorizedClientService.removeAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );

            // Redirect to the OIDC provider's logout endpoint
            String logoutUrl = "http://localhost:8081/logout";  // Replace with the actual OIDC provider logout URL
            String postLogoutRedirectUri = "http://localhost:8081/home";  // Redirect to home after logout
            response.sendRedirect(logoutUrl + "?post_logout_redirect_uri=" + postLogoutRedirectUri);
        } else {
            response.sendRedirect("/home");  // Fallback if not an OAuth2AuthenticationToken
        }
    }
}
