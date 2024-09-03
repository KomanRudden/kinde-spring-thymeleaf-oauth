package com.kinde.oauth.controller;

import com.kinde.KindeClient;
import com.kinde.KindeClientBuilder;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.Map;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
@Slf4j
public class KindeController {

    private final WebClient webClient;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public KindeController(WebClient webClient, OAuth2AuthorizedClientService authorizedClientService) {
        this.webClient = webClient;
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping(path = "/dashboard")
    public String dashboard(Model model, @RegisteredOAuth2AuthorizedClient("kinde") OAuth2AuthorizedClient authorizedClient) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("fullName", user.getUserInfo().getFullName());
            model.addAttribute("token", user.getIdToken().getTokenValue());
        }

        // @formatter:off
        String userprofile = this.webClient
                .get()
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        // @formatter:on
        model.addAttribute("userprofile", userprofile);

        return "dashboard";
    }

    @GetMapping(path = "/home")
    public String home(Model model) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof DefaultOidcUser user) {
            model.addAttribute("username", user.getUserInfo().getFullName());
        }
        return "home";
    }

    @GetMapping(path = "/userprofile")
    public String logout(Model model,
                         @RegisteredOAuth2AuthorizedClient("kinde") OAuth2AuthorizedClient authorizedClient) {

        // @formatter:off
        String userprofile = this.webClient
                .get()
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        // @formatter:on
        model.addAttribute("userprofile", userprofile);
        return "userprofile";
    }

    @GetMapping(path = "/properties")
    public String properties(Model model, OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();

        KindeClient kindeClient = KindeClientBuilder
                .builder()
                .domain("https://koman.kinde.com")
                .clientId("a06a72f6df3642fe85e99e4084ddf866")
                .clientSecret("Ts3GjhZrDomohSMGDzhzjOgiK1SYXo7ZINzd73B6qywMBOoT8viHq")
                .redirectUri("http://localhost:8081")
                .addScope("openid")
                .build();
        model.addAttribute("userinfo", kindeClient.clientSession().retrieveUserInfo().getUserInfo());

        return "api";
    }

    @GetMapping(path = "/api")
    public String api(Model model, OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(),
                authentication.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        model.addAttribute("access_token", accessToken);

        return "api";
    }
}
