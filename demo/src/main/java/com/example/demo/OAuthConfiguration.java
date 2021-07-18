package com.example.demo;


import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
//import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 
 * This class was developed step by step
 * 1. configure
 * 2. Added @value , jwtdecoder and adding it to configure .decoder(jwtDecoder());
 * 3. cors .cors()        .configurationSource(corsConfigurationSource())
 * 
 * @author sarav
 *
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
@Configuration
@PropertySource("application-oauth2.properties")
public class OAuthConfiguration extends WebSecurityConfigurerAdapter {
	
//	@Value(value = "${auth0.apiAudience}")
//	private String apiAudience;
//	
//	@Value(value = "${auth0.issuer}")
//	private String issuer;

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//	    JwtWebSecurityConfigurer
//        .forRS256(apiAudience, issuer)
//        .configure(http)
//        .authorizeRequests()
//        .antMatchers(HttpMethod.GET, "/api/**").permitAll()
////        .antMatchers(HttpMethod.GET, "/api/v1/activity/**").permitAll()
//        .antMatchers(HttpMethod.POST, "/api/**").permitAll()
//        .antMatchers(HttpMethod.POST, "/admin/**").permitAll()
//        .antMatchers(HttpMethod.GET, "/admin/**").permitAll()
//        .antMatchers(HttpMethod.DELETE, "/admin/**").permitAll()
////        .antMatchers(HttpMethod.GET, "/admin/**").hasAuthority("view:courses")
//        .antMatchers(HttpMethod.GET, "/api/v1/question/**").hasAuthority("view:account")
//        .antMatchers(HttpMethod.GET, "/api/v1/students/**").permitAll()
////        .hasAuthority("view:account")
//        .anyRequest().authenticated();
//	}

//	  @Value("${auth0.audience}")
//	  private String audience;
//
//	  @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
//	  private String issuer;
	  
	 @Override
	  protected void configure(HttpSecurity http) throws Exception {
	    http.authorizeRequests()
//	      .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
//		    .antMatchers("/**/*.{js,html,css}").permitAll()
//		    .antMatchers("/**/*.{js,html,css}","/oauth_login","/login", "/loginFailure", "/").permitAll()
		    .antMatchers("/**/*.{js,html,css}","/test","/oauth_login","/login", "/loginFailure", "/", "/error", "/api/all", "/api/auth/**", "/oauth2/**", "/index.html", "/*.js.map", "/assets/img/*.png", "/favicon.ico").permitAll()
//	        .antMatchers("/").permitAll()
	        .antMatchers(HttpMethod.GET, "/api/**").permitAll()
	        
	        .antMatchers(HttpMethod.POST, "/root/**").hasAuthority("ROLE_producer")
	        .antMatchers(HttpMethod.POST, "/admin/**").hasAuthority("ROLE_producer")
	        .antMatchers(HttpMethod.GET, "/admin/**").hasAuthority("ROLE_producer")
	        .antMatchers(HttpMethod.DELETE, "/admin/**").hasAuthority("ROLE_producer")
	        .antMatchers(HttpMethod.PATCH, "/api/**").permitAll()
//	        .antMatchers(HttpMethod.GET, "/admin/**").hasAuthority("view:courses")
	        
//	        .mvcMatchers(HttpMethod.GET, "/api/v1/students/**").permitAll()
	        .anyRequest()
            .authenticated()
            .and()
//            .cors()
//            .configurationSource(corsConfigurationSource())
//            .and()
//            .oauth2ResourceServer()
//            .jwt()
//            .decoder(jwtDecoder())
//            .jwtAuthenticationConverter(jwtAuthenticationConverter());
	          .oauth2Login()
	//          .loginPage("/oauth_login")
	          .authorizationEndpoint()
	          .baseUri("/oauth2/authorize-client")
	          .authorizationRequestRepository(authorizationRequestRepository())
	          .and()
	          .tokenEndpoint()
	          .accessTokenResponseClient(accessTokenResponseClient())
	          .and()
	          .defaultSuccessUrl("/loginSuccess")
	          .failureUrl("/loginFailure");            
            
	  }
	 
	 

//	 
//	  JwtDecoder jwtDecoder() {
//		    OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
//		    OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
//		    OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);
//
//		    NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
//		    jwtDecoder.setJwtValidator(validator);
//		    return jwtDecoder;
//		  }
	  
	  
	    CorsConfigurationSource corsConfigurationSource() {
	        CorsConfiguration configuration = new CorsConfiguration();
	        configuration.setAllowedMethods(
//	        		List.of(//java 9
	        		Arrays.asList(
	                HttpMethod.GET.name(),
	                HttpMethod.PUT.name(),
	                HttpMethod.POST.name(),
	                HttpMethod.DELETE.name(),
	                HttpMethod.PATCH.name()
	        			)
	        		);

	        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	        source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());
	        return source;
	    }
	    
//	    JwtAuthenticationConverter jwtAuthenticationConverter() {
//	        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
//	        converter.setAuthoritiesClaimName("permissions");
//	        converter.setAuthorityPrefix("");
//
//	        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
//	        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
//	        return jwtConverter;
//	    }
	    
//	    JwtAuthenticationConverter jwtAuthenticationConverter() {
//	        CustomAuthoritiesConverter customAuthoritiesConverter = new CustomAuthoritiesConverter();
//	        JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
//	        authenticationConverter.setJwtGrantedAuthoritiesConverter((Converter<Jwt, Collection<GrantedAuthority>>) customAuthoritiesConverter);
//	        return authenticationConverter;
//	    }

	    static class CustomAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
	        // extract authorities from "scope", "https://example.com/role", "https://example.com/group", and "permissions" claims.
	        private static final Map<String, String> CLAIMS_TO_AUTHORITY_PREFIX_MAP = new HashMap<String, String>() {{
//	            put("scope", "SCOPE_");
//	            put("https://example.com/role", "ROLE_");
	            put("http://demozero.net/roles","ROLE_");
//	            put("https://example.com/group", "GROUP_");
	            put("permissions", "PERMISSION_");
	        }};

	        @Override
	        public Collection<GrantedAuthority> convert(Jwt jwt) {
	            return CLAIMS_TO_AUTHORITY_PREFIX_MAP.entrySet().stream()
	                .map(entry -> getAuthorities(jwt, entry.getKey(), entry.getValue()))
	                .flatMap(Collection::stream)
	                .collect(Collectors.toList());
	        }

	        private Collection<GrantedAuthority> getAuthorities(Jwt jwt, String authorityClaimName, String authorityPrefix) {
	            Object authorities = jwt.getClaim(authorityClaimName);
	            if (authorities instanceof String) {
	                if (StringUtils.hasText((String) authorities)) {
	                    List<String> claims = Arrays.asList(((String) authorities).split(" "));
	                    return claims.stream()
	                        .map(claim -> new SimpleGrantedAuthority(authorityPrefix + claim))
	                        .collect(Collectors.toList());
	                } else {
	                    return Collections.emptyList();
	                }
	            } else if (authorities instanceof Collection) {
	                Collection<String> authoritiesCollection = (Collection<String>) authorities;
	                return authoritiesCollection.stream()
	                    .map(authority -> new SimpleGrantedAuthority(authorityPrefix + authority))
	                    .collect(Collectors.toList());
	            }
	            return Collections.emptyList();
	        }
	    }
	    
	    
	    
	    @Bean
	    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
	        return new HttpSessionOAuth2AuthorizationRequestRepository();
	    }

	    @Bean
	    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
	        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
	        return accessTokenResponseClient;
	    }

	    // additional configuration for non-Spring Boot projects
	    private static List<String> clients = Arrays.asList("google");

//	    @Bean
	    public ClientRegistrationRepository clientRegistrationRepository() {
	        List<ClientRegistration> registrations = clients.stream()
	            .map(c -> getRegistration(c))
	            .filter(registration -> registration != null)
	            .collect(Collectors.toList());

	        return new InMemoryClientRegistrationRepository(registrations);
	    }

//	    @Bean
	    public OAuth2AuthorizedClientService authorizedClientService() {
	        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
	    }

	    private static String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";

	    @Autowired
	    private Environment env;

	    private ClientRegistration getRegistration(String client) {
	        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

	        if (clientId == null) {
	            return null;
	        }

	        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
	        if (client.equals("google")) {
	            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
	                .clientId(clientId)
	                .clientSecret(clientSecret)
	                .build();
	        }

	        return null;
	    }  
	    
}