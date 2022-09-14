package pers.yewin.springsecurityjwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pers.yewin.springsecurityjwt.filter.CustomAuthenticationFilter;
import pers.yewin.springsecurityjwt.filter.CustomAuthorizationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.security
 */

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor // inject final userDetailsService and bcryptPasswordEncoder by creating constructor based dependency injection instead of using @Autowire
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bcryptPasswordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /**
         * This method is to add our database username password which are already in spring UserDetailsService class to spring authentication manger
         * to do validation in attemptAuthentication method of CustomAuthenticationFilter class .
         * Here we don't do authenticate with inMemoryAuthentication, and other type of authentication,
         * We do authenticate with our own database (checking username password from our database with user input username password)
         */
        auth.userDetailsService(userDetailsService).passwordEncoder(bcryptPasswordEncoder); // inject BCryptPasswordEncoder to userDetailService
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        /**
         * This method is to control all config for Authorization and Security.
         * This method decide which user and role can only access which api (that's call authorization)
         * This method can not only check user and role for accessing api but also allow permitting to access api for any user and role.
         */


        // add authenticationManager to customAuthenticationFilter, to check login authentication
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());

        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); // set for don't save user session data

        // allow for all api endpoint url for any role and any user without defining access api permission by which roles.
        // we comment out below line because we want to do authorization for each api endpoints (authorization - decide which user and roles can access which api)
//        http.authorizeRequests().anyRequest().permitAll();

        /** You don't need to add application main path in front of request api url (context path which define in properties, /spring-security-jwt path is for this app, and I don't add that in below filter url.)  **/


        // set not to check api permission by role to login api endpoint. Login api and token refresh api can call from every user and roles.
        // because login api and token refresh don't need to check for user and role as it need to call for all user and role when the user want to login to our application.
        // login api are already existed in spring security UsernamePasswordAuthenticationFilter class and already extend by our CustomAuthenticationFilter class.
        http.authorizeRequests().antMatchers("/login", "/user/token/refresh").permitAll();


        // If we don't want to use spring built-in login url,
        // we can add (create) our own base url in front of built-in login url like below
        // if you want to add custom login url, you can comment out above login permit all line, and open below two comment out line
        // eg. we can add custom url /EmployeeApplication/login, below comment code is example

        /*
        customAuthenticationFilter.setFilterProcessesUrl("/user/login");

        // If we set our own url like above, we need to add that url to get permission which not to check role, etc.
        http.authorizeRequests().antMatchers("/user/login", "/user/token/refresh").permitAll();*/


        /** You don't need to add application main path in front of request api url (context path which define in properties, /spring-security-jwt path is for this app, and I don't add that in front of below filter url cause it's no need)  **/

        // set all GET api after user endpoint (eg. getAllUser, getUserByEmail api) can access from User who has Normal User role and all others roles (** mean all are allow behind user/ endpoint)
        // here, you can use hasAnyRole instead of hasAnyAuthority, if you use hasAnyAuthority, you need to add ROLE prefix text in front of roles but after spring security version 4, you don't need to add that prefix and so, I don't add that.
        http.authorizeRequests().antMatchers(GET, "/user/**").hasAnyAuthority("NORMAL_USER", "MANAGER", "ADMIN" , "SUPER_ADMIN"); // all roles should access user get api request. All logic are depends on you and your application as this is demo app.

        // set all POST api after user/save endpoint can access Only from User who has Admin and Super Admin User role
        // should only admin and super admin can call for saving user api.
        // for some cases, normal user can call some save api (like register user (save user)) but can't call delete user api, (some application can create user by all and that's depend on your application logic),
        // for that case you should let normal user can call save user api by adding NORMAL USER role in below, but can't call delete user api, so, you should set delete user api can only be call from ADMIN and SUPER ADMIN.
        // so, all logic are depends on your application business logic.
        /** All access permission logic are depends on you and your application, please note that this is demo app. **/
        http.authorizeRequests().antMatchers(POST, "/user/createUser").hasAnyAuthority("MANAGER", "ADMIN", "SUPER_ADMIN");

        // set only admin and super admin can call all POST method api behind role/ url endpoint with ** (** mean all behind /)
        // this is demo, and you can add that in above line 85, eg. /spring-security-jwt/user/**,
        // But for some case (some application can create (register) user by all and that's depend on your application logic),
        // if you let Normal user and Manager role can add user (you let call saveUser by normal user), you should separate this adding role like below.
        http.authorizeRequests().antMatchers(POST, "/user/role/**").hasAnyAuthority("ADMIN", "SUPER_ADMIN");

        http.authorizeRequests().anyRequest().authenticated(); // set any api request (any api call) must be authenticated, means successfully login.

        // you can also add isRememberMe and isAnonymous request.

        // add our CustomAuthenticationFilter class for authentication into Spring Security Filter., we put logic to check login is valid or not
        http.addFilter(customAuthenticationFilter);



        // add our CustomAuthorizationFilter class and UsernamePasswordAuthenticationFilter for checking Authorization into Spring Security Filter.
        // we put validation token login in that CustomAuthorizationFilter class to check (validate) user token is valid or not.
        // filterBefore means application will check authorization before on every api request and every api process
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }


}
