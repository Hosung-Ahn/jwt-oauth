package com.oauth2.model;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class KeycloakUser extends OAuth2ProviderUser{
    public KeycloakUser(OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return null;
    }

    @Override
    public String getProvider() {
        return super.getProvider();
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }
}
