package com.oauth2.model;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Map;

public class NaverUser extends OAuth2ProviderUser{
    public NaverUser(OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return getAttributes().get("id").toString();
    }

    @Override
    public String getProvider() {
        return super.getProvider();
    }

    @Override
    public String getName() {
        return getAttributes().get("name").toString();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }
}
