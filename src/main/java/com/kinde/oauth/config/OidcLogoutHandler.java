package com.kinde.oauth.config;

import com.kinde.KindeClient;
import com.kinde.KindeClientBuilder;
import com.kinde.KindeClientSession;
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

            authorizedClientService.removeAuthorizedClient(
                    oauthToken.getAuthorizedClientRegistrationId(),
                    oauthToken.getName()
            );

            KindeClient kindeClient = KindeClientBuilder.builder()
                    .domain("https://koman.kinde.com")
                    .clientId("a06a72f6df3642fe85e99e4084ddf866")
                    .clientSecret("Ts3GjhZrDomohSMGDzhzjOgiK1SYXo7ZINzd73B6qywMBOoT8viHq")
                    .logoutRedirectUri("http://localhost:8081")
                    .build();
            KindeClientSession kindeClientSession = kindeClient.initClientSession("test", null);
            kindeClientSession.logout();
        } else {
            response.sendRedirect("/home");  // Fallback if not an OAuth2AuthenticationToken
        }
    }
}
