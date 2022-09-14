package pers.yewin.springsecurityjwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pers.yewin.springsecurityjwt.model.entity.Role;
import pers.yewin.springsecurityjwt.model.entity.Users;
import pers.yewin.springsecurityjwt.repository.RoleRepository;
import pers.yewin.springsecurityjwt.repository.UsersRepository;

import javax.transaction.Transactional;
import java.util.*;

/**
 * @author: Ye Win
 * @created: 28/08/2021
 * @project: spring-security-jpa-jwt
 * @package: pers.yewin.springsecurityjwt.service
 */

@Service
@Transactional
@RequiredArgsConstructor // inject final user repository, role repository, password encoder by creating constructor based dependency injection instead of using @Autowire
@Slf4j // for logging
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UsersRepository usersRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        /**
         * this method is important
         * this method retrieve our user information from database by name (here I use email as I think it's unique in my application).
         * and bind that our user information into spring security built-in User object,
         * so that spring security can check our user and role
         * so, we can define whatever we want role name for authorization (authorization - decide which user and roles can access which api)
         **/

        Users users = getByEmail(email); // to get unit value
        if(users==null) {
            log.error("User not found by email: {}", email);
            // authentication manager will take care if user not found exception in CustomAuthenticationFilter class (method - unsuccessfulAuthentication)
            throw new UsernameNotFoundException("User not found in the database");
        }else {
            log.info("user is existed in the database: {}", email);
        }

        // check for role not found error,
        // even those user who don't have role can get token by login api, he/she can't call to other apis as he don't have any role.
        // you can return error with runtimeException here if you don't even return token to user who don't have role.
        // So, If you created new user and that user want to login and can call other api as well, we need to add role to that user first by calling add role to user api.
        if(users.getRoleList().isEmpty()){
            log.warn("role not found.");
            return new User(users.getEmail(), users.getPassword(), new ArrayList<>());
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        users.getRoleList().forEach(
                role -> authorities.add(new SimpleGrantedAuthority(role.getName())) // tail only role name and add to authorities, remove (left) role id and others fields if existed
        );
        // add our user information into spring security built-in user object
        // authentication manager will take care whether success or fail (eg. if input password is wrong with our db password) in CustomAuthenticationFilter class (method - successfulAuthentication or unsuccessfulAuthentication)
        return new User(users.getEmail(), users.getPassword(), authorities); // here, I added email as I will use that email as username in spring built-in user object and that is unique in my system.
    }

    @Override
    public List<Users> getAllUsers() {
        log.info("get all users");
        return usersRepository.findAll();
    }

    @Override
    public Users getByEmail(String email) {
        log.info("get user by email: {}", email);
        return usersRepository.findByEmail(email);
    }

    @Override
    public ResponseEntity saveUser(Users user) {
        log.info("saving user: {}",user);
        Map<String, String> errorMap = new HashMap<String, String>();

        // check email, and you can add email format validation logic here, This is demo project and I don't check that format validation now.
        if(user!=null && user.getEmail()!=null){

            Users dbUser = getByEmail(user.getEmail());

            // if user is existed by finding email, we don't let insert same email into db
            if(dbUser!=null) {
                /**
                 * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields,
                 * but this is demo project so, I don't do that.
                  */
                log.error("User is already existed in the database: {}", user.getEmail());
                errorMap.put("error", "User is already existed in System");
                return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
            }

            // before saving into user table, we do encode password because we don't want to save plain text password in db,
            // because if attackers can access our db, they can easily know users' passwords.
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user = usersRepository.save(user); // insert into db
            /**
             * we should return with only one response object for all api response instead of user object eg. ResponseModel which include status, message, data fields,
             * but this is demo project so, I don't do that.
             */
            return new ResponseEntity<>(user, HttpStatus.CREATED);
        }
        else {
            /**
             * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            errorMap.put("error", "Input is null");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public ResponseEntity saveRole(Role role) {
        log.info("saving role: {}",role);
        Map<String, String> errorMap = new HashMap<String, String>();

        // check role name
        if(role != null && role.getName()!=null) {

            Role dbRole = roleRepository.findByName(role.getName());

            // if role is existed, we don't let insert same role name into db
            if(dbRole!=null) {
                /**
                 * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
                 * but this is demo project so, I don't do that.
                 */
                log.error("Role Name is already existed in the database: {}", role.getName());
                errorMap.put("error", "Role is already in System");
                return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
            }

            role = roleRepository.save(role);

            /**
             * we should return with only one response object for all api response instead of role object. eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            return new ResponseEntity<>(role, HttpStatus.CREATED);
        }
        else {
            /**
             * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            errorMap.put("error", "Input is null");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public ResponseEntity addRoleToUser(String email, String roleName) {
        log.info("add role to user, email: {}, roleName: {}",email, roleName);
        Map<String, String> errorMap = new HashMap<>();

        // you can check email null and email format here. This is demo project and I don't check that now.
        Users user = usersRepository.findByEmail(email);
        if(user== null){
            /**
             * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            log.error("Couldn't find user by email: {}", email);
            errorMap.put("error", "User Not Found");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }
        Role role = roleRepository.findByName(roleName);
        if(role== null){
            /**
             * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            log.error("Couldn't find role by role name: {}", roleName);
            errorMap.put("error", "Role Name Not Found, Please add Role Name that you want.");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }

        // check if user input role name is already existed (already added) in user object, if existed, put that into Optional<Role> Object.
        Optional<Role> foundRole = user.getRoleList().stream().filter(roleObj -> roleObj.getName().equals(roleName)).findFirst();

        // check for role name is existed
        if(foundRole.isPresent()){
            /**
             * we should return with only one response object for all api response eg. ResponseModel with status, message, data fields
             * but this is demo project so, I don't do that.
             */
            log.error("Input role name is already existed in user: {}, roleName: {}", email, roleName);
            errorMap.put("message", "Input role is already added in user");
            return new ResponseEntity<>(errorMap, HttpStatus.BAD_REQUEST);
        }

        user.getRoleList().add(role); // we don't need to call save method again as we declared @transactional, it will refresh and upload db, and do rollback if got error.
        return ResponseEntity.ok().build();
    }

}
