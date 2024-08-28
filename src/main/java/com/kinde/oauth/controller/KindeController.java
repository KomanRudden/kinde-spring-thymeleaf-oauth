package com.kinde.oauth.controller;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class KindeController {

    private final OAuth2AuthorizedClientService authorizedClientService;

    public KindeController(OAuth2AuthorizedClientService authorizedClientService) {
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/api/auth/kinde_callback")
    public String callback(@AuthenticationPrincipal OidcUser principal) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = ((OidcUser) authentication.getPrincipal());
        }
        return "users";
    }

    @GetMapping(path = "/")
    public String index(Model model) {
        // Need to look up principal here. By including it as a method param, Spring will redirect to login (which isn't required for this endpoint)
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("username", user.getUserInfo().getFullName());
        }
        return "public";
    }

    @GetMapping(path = "/test")
    public String test(OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        return "Access Token: " + accessToken;
    }
}
