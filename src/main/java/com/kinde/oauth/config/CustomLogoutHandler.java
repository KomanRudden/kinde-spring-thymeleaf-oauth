package com.kinde.oauth.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

    private final RestTemplate restTemplate;

    public CustomLogoutHandler() {
        this.restTemplate = new RestTemplate();
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // Custom logic before logout
        if (authentication != null) {
            System.out.println("User '" + authentication.getName() + "' is logging out.");

            // Example: Clear any custom session attributes
            request.getSession().removeAttribute("SPRING_SECURITY_CONTEXT");

            if (authentication.getPrincipal() instanceof OidcUser oidcUser) {
                String accessToken = oidcUser.getIdToken().getTokenValue();

                // Revoke the access token
                revokeAccessToken(accessToken);

                System.out.println("User '" + authentication.getName() + "' is logging out.");
            }
        }

        // Invalidate the session
        request.getSession().invalidate();

        // Optionally, redirect to another page
        response.setStatus(HttpServletResponse.SC_OK);
        try {
            response.sendRedirect("/home");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // TODO clearing session upon logout not working
    private void revokeAccessToken(String accessToken) {
        String revokeUrl = "https://koman.kinde.com/revoke";

        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        headers.setBasicAuth("a06a72f6df3642fe85e99e4084ddf866", "Ts3GjhZrDomohSMGDzhzjOgiK1SYXo7ZINzd73B6qywMBOoT8viHq");

        String body = "token=" + accessToken;

        HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.exchange(revokeUrl, HttpMethod.POST, requestEntity, String.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            System.out.println("Access token revoked successfully.");
        } else {
            System.out.println("Failed to revoke access token.");
        }
    }
}

