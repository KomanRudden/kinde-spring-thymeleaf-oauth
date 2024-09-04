package com.kinde.oauth.service;

import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class KindeService {

    private final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager;

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final RestTemplate restTemplate = new RestTemplate();

    public KindeService(AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager,
                        OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientManager = authorizedClientManager;
        this.authorizedClientService = authorizedClientService;
    }
}

