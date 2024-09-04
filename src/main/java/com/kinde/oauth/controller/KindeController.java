package com.kinde.oauth.controller;

import com.kinde.oauth.service.KindeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.view.RedirectView;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
@Slf4j
public class KindeController {

    private final KindeService kindeService;
    private final WebClient userProfileClient;
    private final WebClient logoutClient;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public KindeController(KindeService kindeService,
                           @Qualifier("userProfile") WebClient userProfileClient,
                           @Qualifier("logout") WebClient logoutClient,
                           OAuth2AuthorizedClientService authorizedClientService) {
        this.kindeService = kindeService;
        this.userProfileClient = userProfileClient;
        this.logoutClient = logoutClient;
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping(path = "/home")
    public String home(Model model) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("username", user.getUserInfo().getFullName());
        }
        return "home";
    }

    // TODO
    @GetMapping("/logout")
    public String logout() {
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


    // TODO
    @GetMapping("/call-api")
    public String callApi(@AuthenticationPrincipal OAuth2AuthenticationToken authentication) {
        return kindeService.makeApiCall(authentication);
    }

    // TODO
    @GetMapping("/call-api-with-manager")
    public String callApiWithManager(@AuthenticationPrincipal OAuth2AuthenticationToken authentication) {
        return kindeService.makeApiCallWithManager(authentication);
    }

    @GetMapping("/")
    public String root() {
        return "home";
    }
}
