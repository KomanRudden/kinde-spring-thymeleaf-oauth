package com.kinde.oauth.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
@Slf4j
public class KindeController {

    private final WebClient userProfileClient;

    public KindeController(@Qualifier("userProfile") WebClient userProfileClient) {
        this.userProfileClient = userProfileClient;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('admins')")
    public String adminEndpoint() {
        return "home";
    }

    @GetMapping("/read")
    @PreAuthorize("hasRole('read')")
    public String readEndpoint() {
        return "home";
    }

    @GetMapping(path = "/home")
    public String home(Model model) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("username", user.getUserInfo().getFullName());
        }
        return "home";
    }

    @GetMapping(path = "/dashboard")
    public String dashboard(Model model,
                            @RegisteredOAuth2AuthorizedClient("kinde") OAuth2AuthorizedClient authorizedClient) {

        // Extracting values from Principal
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("fullName", user.getUserInfo().getFullName());
            model.addAttribute("id_token", user.getIdToken().getTokenValue());
        }

        // Extracting access token via OAuth client
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        model.addAttribute("access_token", accessToken);

        // Extracting user profile via Spring Webflux client
        String userprofile = this.userProfileClient
                .get()
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        model.addAttribute("userprofile", userprofile);

        return "dashboard";
    }
}
