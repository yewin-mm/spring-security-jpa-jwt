package pers.yewin.springsecurityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.filter
 */

@Slf4j // for logging
public class CustomAuthorizationFilter extends OncePerRequestFilter { // OncePerRequestFilter will check for every api request.
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        try {

            /**
             * This method is to validate for each api request by checking Access Token is right or wrong in header field,
             * So, attacker can't call direct link without Access Token, eg. he can't call localhost:8080/user/delete api, etc. That is what we call one of the security.
             * When the request (api call from frontend or other place like postman, other service, third party system, etc.) was come, this method catch for each request and take access token inside header field and check whether token is right or wrong.
             * But for the login and token/refresh api, application need to pass from validating (checking Access token).
             * Because For the login api -> frontend or other place don't have access token for the first step login api as they will get tokens after login.
             * For token/refresh api, that api call will happen after access token was expired case, so, if you let check token/refresh api in here, that will always response wrong token and got role not found error as I didn't add role in that token.
             * Please note that, All api requests are checking only Access Token and Refresh token purpose is only to re-generate Access Token, RT is not for validate (checking).
             *
             */

            // check for login api endpoint or not,
            // if login api or token refresh api, we let them authenticate in CustomAuthenticationFilter for login authentication whether success or not.
            // if not login or token/refresh, we will do for authorization (decide what role will get permission for which api endpoints) by checking JWT by separating (decoding) username and  roles from that JWT.
            if (httpServletRequest.getServletPath().equals("/login") || httpServletRequest.getServletPath().equals("/user/token/refresh")) {

                // to keep working login and token refresh api process
                // if login, it will go to CustomAuthenticationFilter class and return tokens and if not so, it will go to token/refresh api.
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            } else {
                String authorizationHeader = httpServletRequest.getHeader(AUTHORIZATION);
                String bearer = "Bearer "; // include space behind Bearer as key will follow after space

                // check to make sure token key from header is starting with Bearer
                if (authorizationHeader != null && authorizationHeader.startsWith(bearer)) {
                    String token = authorizationHeader.substring(bearer.length()); // cut header for starting bearer keyword and take all key text behind bearer by substring method.

                    /**
                     * you can declare below password key (secret) with final static field under utility constant class,
                     * so that can be use in other place like token/refresh api, CustomAuthenticationFilter class, etc.
                     * So that you can easily change it in one place if you want (that will impact to others as all place use that field value)
                     * and you don't need to worry about secret mismatched case.
                     * if not, you need to re-write for same value in others place like token/refresh api and CustomAuthenticationFilter class, and so, it can get typing wrong and it will lead duplicate same code.
                     */

                    // create algorithm object by password key that password key must need to be same with Token generating secret key. which is generated in CustomAuthenticationFilter class.
                    Algorithm algorithm = Algorithm.HMAC256("MyAppSecurityPassword".getBytes());
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build(); // create JWT verify with algorithm to verify user input token.
                    DecodedJWT decodedJWT = jwtVerifier.verify(token); // decode token
                    String email = decodedJWT.getSubject(); // subject will be email as we gave that in CustomAuthenticationFilter class.

                    // retrieve roles from claim by using key 'roles' as we gave that in CustomAuthenticationFilter class.
                    String [] roles = decodedJWT.getClaim("roles").asArray(String.class); // we gave that as String array (Authorities), so we need to convert to String array when we pull that roles.

                    // check if roles is null or not empty for user.
                    if(roles != null && roles.length != 0) {

                        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

                        stream(roles).forEach(role -> {
                            authorities.add(new SimpleGrantedAuthority(role)); // convert string array roles to SimpleGrantedAuthority list (authorities) because spring framework only know this object for permission authorities cases.
                        });

                        // we set email instead of username as our application use email for unique identifier, and we don't need to know password as it's already authenticated, so we put null ,and we add authorities which included roles.
                        UsernamePasswordAuthenticationToken usrNamePwdAuthenticationToken = new UsernamePasswordAuthenticationToken(email, null, authorities);
                        // put authenticated token into spring security context, means we let spring security know, to do for authorization (decide what role will get permission for which api endpoints)
                        SecurityContextHolder.getContext().setAuthentication(usrNamePwdAuthenticationToken);
                        filterChain.doFilter(httpServletRequest, httpServletResponse); // to keep working other APIs process.

                    }else {

                        // if roll is null or empty, we don't let user do anything,
                        // it can be two types of user for roll null case.
                        // 1. If created user, but not define roll, it will roll null case. we don't let that user get inside our system without role.
                        // So, after you creating user, you need to add role to user first if you want that user to go inside application.
                        // 2. If input token is refresh token not access token, there is no roll for that token as we didn't put role in refresh token when we created that token in successfulAuthentication method of CustomAuthenticationFilter.
                        // So, we don't validate with refresh token to our api access, and it will get null error too.
                        // So, we don't let user can call api with refresh token except token/refresh api, that is already check in above if statement.
                        filterChain.doFilter(httpServletRequest, httpServletResponse);
                    }

                }else {
                    // if token is not start with bearer, it will return automatic error.
                    filterChain.doFilter(httpServletRequest, httpServletResponse); // to keep working other api process, and it will return fail as it's wrong format for token starting character
                }
            }
        }catch (Exception e) {
//            e.printStackTrace();
            /**
             * Spring security will check token in above and if it's invalid or if it's expired, it will come here.
             */
            log.error("error: {}", e.getMessage());
            httpServletResponse.setHeader("error ", e.getMessage());
            httpServletResponse.setStatus(FORBIDDEN.value());
//            httpServletResponse.sendError(FORBIDDEN.value());

            Map<String, String> errorJson = new HashMap<>();
            errorJson.put("error: ", e.getMessage());
            errorJson.put("code: ", String.valueOf(FORBIDDEN.value()));
            errorJson.put("message: ", "Your input token is something wrong");
            httpServletResponse.setContentType(APPLICATION_JSON_VALUE); // set return value as json type to show return value in body part.

            /**
             * we can create custom response class for response (eg. response class may include these fields - status, message, access token, refresh token, etc).
             * So that frontend developer will know that whether token is expired or format wrong or etc.
             * So, if he knew the token is expired, he can call token/refresh api or etc. to do other logic.
             * Here is demo project, so, I don't go with custom class and this is for testing purpose.
             */

            // return json type data by writing output stream to httpServletResponse
            new ObjectMapper().writeValue(httpServletResponse.getOutputStream(), errorJson);
        }
    }
}
