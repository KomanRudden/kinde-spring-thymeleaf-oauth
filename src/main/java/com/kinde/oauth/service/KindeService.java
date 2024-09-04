package com.kinde.oauth.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

@Service
public class KindeService {

    private final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager;

    private OAuth2AuthorizedClientService authorizedClientService;

    private final RestTemplate restTemplate = new RestTemplate();

    public KindeService(AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager,
                        OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientManager = authorizedClientManager;
        this.authorizedClientService = authorizedClientService;
    }

    public String makeApiCall(Authentication authentication) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        // Retrieve the OAuth2AuthorizedClient
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(),
                oauthToken.getName());

        if (authorizedClient == null) {
            // If no authorized client is found, the user must be re-authenticated
            throw new IllegalStateException("No authorized client found. User must authenticate.");
        }

        // Use the access token to make an API call
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        String resourceUrl = "https://api.example.com/protected-resource";
        try {
            return restTemplate.getForObject(resourceUrl, String.class, accessToken.getTokenValue());
        } catch (HttpClientErrorException e) {
            // Handle errors (e.g., token expiration)
            if (e.getStatusCode().is4xxClientError()) {
                // Consider refreshing the token
                throw new IllegalStateException("Token expired. Consider refreshing the token.", e);
            }
            throw e;
        }
    }

    // Another method that automatically manages the client (refreshes token if needed)
    public String makeApiCallWithManager(Authentication authentication) {
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;

        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(
                OAuth2AuthorizeRequest.withClientRegistrationId(oauthToken.getAuthorizedClientRegistrationId()).build());

        if (authorizedClient == null) {
            throw new IllegalStateException("Authorization failed. User must authenticate.");
        }

        String resourceUrl = "https://api.example.com/protected-resource";
        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        return restTemplate.getForObject(resourceUrl, String.class, accessToken.getTokenValue());
    }
}

